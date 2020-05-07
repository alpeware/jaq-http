(ns jaq.http.xrf.html
  (:require
   [goog.dom :as dom]
   [clojure.string :as string]
   [cljs.core]
   [clojure.browser.event :as events]
   [goog.net.XhrIo :as xhr]
   [incremental-dom :as incd])
  (:import
   [goog.net EventType XhrIo]))

;; From Weavejester's Hiccup: https://github.com/weavejester/hiccup/blob/master/src/hiccup/compiler.clj
(def ^{:doc "Regular expression that parses a CSS-style id and class from a tag name." :private true}
  re-tag #"([^\s\.#]+)(?:#([^\s\.#]+))?(?:\.([^\s#]+))?")

;; incremental dom
;; adapted from https://github.com/christoph-frick/cljs-incremental-dom/blob/master/src/incdom/core.cljs

(defn extract [elem attrs]
  (let [[_ tag id class] (re-matches re-tag (name elem))
        classes (->> [(:class attrs) (some-> class (string/replace #"\." " "))]
                     (remove empty?))
        classes (when (seq classes)
                  (string/join " " classes))
        attrs (assoc attrs
                     :id (or id (:id attrs))
                     :class classes)]
    [tag (apply dissoc attrs (for [[k v] attrs :when (nil? v)] k))]))

#_(

   (extract :div#id.foo.bar {:id :bar :class "baz"})
   (extract :div#id.foo.bar {:id :bar})
   (extract :div {:key :key})

   )

(defn attr-name
  [attr-name]
  (cond
    (keyword? attr-name) (name attr-name)
    :else (str attr-name)))

(defn attr-value
  [attr-value]
  (cond
    (map? attr-value) (clj->js attr-value)
    (fn? attr-value) attr-value
    :else (str attr-value)))

(defn attr
  [an av]
  (incd/attr
   (attr-name an)
   (attr-value av)))

;; see https://github.com/google/incremental-dom/pull/408
(def attr-props #{:value :disabled :className :checked})

(defn props
  [an av]
  (when (contains? attr-props attr-name)
    (incd/applyProp
     (incd/currentElement)
     (attr-name attr-name)
     (attr-value attr-value))))

(defn element-open
  [elem attrs]
  (let [[tag-name attrs] (extract elem attrs)]
    (incd/elementOpenStart tag-name (:key attrs) nil)
    (run! (partial apply attr) attrs)
    (incd/elementOpenEnd tag-name)
    (run! (partial apply props) attrs)))

;; TODO: calling extract for both open and close
(defn element-close
  [elem]
  (let [[tag-name attrs] (extract elem)]
    (incd/elementClose tag-name)))

(defn element-void
  [elem attrs]
  (do
    (element-open elem attrs)
    (element-close elem)))

(defn text
  [txt]
  (incd/text (str txt)))

(defn patch
  [root fn]
  (incd/patch root fn))

(defn html
  [root]
  (let [[elem & remainder] root
        [attr & remainder] (if (map? (first remainder))
                             remainder
                             (conj remainder {}))]
    (if (empty? remainder)
      (element-void elem attr)
      (do
        (element-open elem attr)
        (doseq [r remainder]
          (cond
            (vector? r) (html r)
            (sequential? r) (doseq [rr r] (html rr))
            :else (text r)))
        (element-close elem)))))

;; move to rf.cljc

(def identity-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc x]
       (rf acc x)))))

(defn result-fn []
  (let [result (volatile! nil)]
    (fn
      ([] @result)
      ([acc] acc)
      ([acc x] (vreset! result x) acc))))

(defn repeatedly-rf [xf]
  (fn [rf]
    (let [val (volatile! nil)
          vacc (volatile! nil)
          init (fn [] (xf (result-fn)))
          xf-rf (volatile! (init))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         #_(@xf-rf acc x)
         (.info js/console "repeatedly")
         (if-let [x' (@xf-rf)]
           (do
             (.info js/console "reset")
             (vreset! xf-rf (init))
             (rf acc x'))
           (@xf-rf acc x)))))))

;;; rf.cljc
(defn bench-rf [xf]
  (fn [rf]
    (let [xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (let [start (.now js/performance)
               x' (xrf acc x)]
           (->> (assoc x'
                       :perf/start start
                       :perf/end (.now js/performance))
                (rf acc'))))))))

(def render-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:event/keys [src target type]
             :dom/keys [hiccup]
             :component/keys [state]
             :as x}]
       (patch src
              (fn []
                (html hiccup)))
       (rf acc x)))))

(defn register! [src type rf x]
  (let [xrf (rf (result-fn))
        acc nil]
    (events/listen src
                   type
                   (fn [e]
                     (xrf acc (assoc x
                                     :context/rf rf
                                     :context/x x
                                     :event/target (.-target e)
                                     :event/type (.-type e)
                                     :event/src (.-currentTarget e)
                                     :event/event e))))))


(defn listen-rf [src type xf]
  (fn [rf]
    (let [xrf (xf (result-fn))
          listen (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:dom/keys [hiccup]
               :as x}]
         (when-not @listen
           (->> (events/listen src
                               type
                               (fn [e]
                                 (xrf acc (assoc x
                                                 :context/rf xrf
                                                 :context/x x
                                                 :event/target (.-target e)
                                                 :event/type (.-type e)
                                                 :event/src (.-currentTarget e)
                                                 :event/event e))
                                 #_(when-let [r (xrf)]
                                     (js/setTimeout
                                      (.info js/console "unlisten" (.-key @listen))
                                      #(goog.events/unlistenByKey (.-key @listen))
                                      0))))
                (vreset! listen)))
         (->> (assoc x :listener/key @listen)
              (rf acc)))))))

(defn listen-once-rf [src type xf]
  (fn [rf]
    (let [xrf (xf (result-fn))
          listen (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:dom/keys [hiccup]
               :as x}]
         (when-not @listen
           (->> (events/listen-once src
                                    type
                                    (fn [e]
                                      (xrf acc (assoc x
                                                      :context/rf xrf
                                                      :context/x x
                                                      :event/target (.-target e)
                                                      :event/type (.-type e)
                                                      :event/src (.-currentTarget e)
                                                      :event/event e))))
                (vreset! listen)))
         (->> (assoc x :listener/key @listen)
              (rf acc)))))))

(defn await-rf [src type]
  (fn [rf]
    (let [once (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:event/keys []
               :as x}]
         (when-not @once
           (->> (events/listen-once src
                                    type
                                    (fn [e]
                                      (rf acc (assoc x
                                                     :context/rf rf
                                                     :context/x x
                                                     :event/target (.-target e)
                                                     :event/type (.-type e)
                                                     :event/src (.-currentTarget e)
                                                     :event/event e))))
                (vreset! once)))
         acc)))))

(defn register-rf [xf]
  (fn [rf]
    (let [listen (volatile! nil)
          xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:event/keys [src type]
               :as x}]
         (when-not @listen
           (->> (events/listen src
                               type
                               (fn [e]
                                 (.info js/console "firing")
                                 (xrf acc (assoc (xrf)
                                                :context/rf xrf
                                                :context/x x
                                                :event/target (.-target e)
                                                :event/type (.-type e)
                                                :event/src (.-currentTarget e)
                                                :event/event e))))
                (vreset! listen))
           #_(->> (assoc x :listener/key @listen)
                (xrf acc)))
         #_acc
         (->> (assoc x :listener/key @listen)
                (rf acc)))))))

(def init-rf
  (comp
   (map (fn [{:component/keys [state input]
              :as x}]
          (assoc x :dom/hiccup [:div.main
                                [:p "Welcome"]])))
   render-rf))

;; setup registry
(defn init []
  (register! (dom/getDocument) :load init-rf x))


;; Network stuff

(def net-events
  (into {}
        (map
         (fn [[k v]]
           [(keyword (.toLowerCase k))
            v])
         (merge
          (js->clj EventType)))))

#_(
   (let [xhr (XhrIo.)
         type (get net-events :ready)]
     #_(events/listen-once xhr type (fn [e] (->> e (.-target) (.getResponseText) (.info js/console))))
     (events/listen xhr type (fn [e] (->> e (.info js/console))))
     #_(doseq [type (keys net-events)]
         (events/listen xhr type (fn [e] (->> e (.info js/console)))))
     (.send xhr "http://localhost:32768/out/goog/base.js"))

   (keys net-events)

   )


#_(

   (dom/getElement "main")

   x
   (-> x :component/state (deref))
   (-> (dom/getDocument) (.querySelector "input") (goog.events/removeAll))
   (-> (dom/getDocument) (.querySelector "button") (goog.events/removeAll))

   )
