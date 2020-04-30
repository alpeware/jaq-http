(ns jaq.http.xrf.client
  (:require
   [goog.dom :as gdom]
   [incremental-dom :as incd]
   [clojure.string :as string]
   ;;[cljs.core]
   ;;[cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
   ;;[cljs.pprint :refer [pprint] :refer-macros [pp]]
   ;;[clojure.browser.dom :as dom]
   [clojure.browser.event :as event]
   [reagent.core :as r]
   [reagent.dom :refer [render]]))

;; from pinot

(def xmlns {:xhtml "http://www.w3.org/1999/xhtml"
            :svg "http://www.w3.org/2000/svg"})

(declare elem-factory)
(def elem-id (atom 0))
(def group-id (atom 0))

(defn as-content [parent content]
  (doseq[c content]
    (let [child (cond
                  (nil? c) nil
                  (map? c) (throw "Maps cannot be used as content")
                  (string? c) (gdom/createTextNode c)
                  (vector? c) (elem-factory c)
                  ;;TODO: there's a bug in clojurescript that prevents seqs from
                  ;; being considered collections
                  (seq? c) (as-content parent c)
                  (.-nodeName c) c)]
      (when child
        (gdom/appendChild parent child)))))

;; From Weavejester's Hiccup: https://github.com/weavejester/hiccup/blob/master/src/hiccup/core.clj#L57
(def ^{:doc "Regular expression that parses a CSS-style id and class from a tag name." :private true}
  re-tag #"([^\s\.#]+)(?:#([^\s\.#]+))?(?:\.([^\s#]+))?")

(defn- normalize-element
  "Ensure a tag vector is of the form [tag-name attrs content]."
  [[tag & content]]
  (when (not (or (keyword? tag) (symbol? tag) (string? tag)))
    (throw (str tag " is not a valid tag name.")))
  (let [[_ tag id class] (re-matches re-tag (name tag))
        [nsp tag]     (let [[nsp t] (string/split tag #":")
                            ns-xmlns (xmlns (keyword nsp))]
                        (if t
                          [(or ns-xmlns nsp) t]
                          [(:xhtml xmlns) nsp]))
        tag-attrs        (into {}
                               (filter #(not (nil? (second %)))
                                       {:id (or id nil)
                                        :class (if class (string/replace class #"\." " "))}))
        map-attrs        (first content)]
    (if (map? map-attrs)
      [nsp tag (merge tag-attrs map-attrs) (next content)]
      [nsp tag tag-attrs content])))

(defn ->coll [c]
  (if (coll? c)
    c
    [c]))

(defn attr
  ([elem attrs]
   (when elem
     (if-not (map? attrs)
       (. elem (getAttribute (name attrs)))
       (do
         (doseq [[k v] attrs]
           (attr elem k v))
         elem))))
  ([elem k v]
   (doseq [el (->coll elem)]
     (. el (setAttribute (name k) v)))
   elem))

(defn parse-content [elem content]
  (let [attrs (first content)]
    (if (map? attrs)
      (do
        (attr elem attrs)
        (rest content))
      content)))

(defn create-elem [nsp tag]
  #_(gdom/createElement tag)
  (. js/document (createElementNS nsp tag)))

(defn elem-factory [tag-def]
  (let [[nsp tag attrs content] (normalize-element tag-def)
        elem (create-elem nsp tag)]
    (attr elem attrs #_(merge attrs {:pinotId (swap! elem-id inc)}))
    (as-content elem content)
    elem))

(defn html [& tags]
  (map elem-factory tags))

(defn dom-clone [elem]
  (. elem (cloneNode true)))

(defn append [elem html]
  (doseq [el (->coll elem)
          tag (->coll html)]
    (gdom/appendChild el (dom-clone tag))))

(defn unappend [elem]
  (doseq [elem (->coll elem)]
    (gdom/removeNode elem)))

(defn before [elem & [sibling]]
  (doseq [el (->coll elem)
          sibling (->coll sibling)]
    (if sibling
      (gdom/insertSiblingBefore (dom-clone sibling) el)
      (gdom/getPreviousElementSibling el))))

(defn after [elem & [sibling]]
  (doseq [el (->coll elem)
          sibling (->coll sibling)]
    (if sibling
      (gdom/insertSiblingAfter (dom-clone sibling) el)
      (gdom/getNextElementSibling el))))

(defn prepend [elem neue]
  (doseq [el (->coll elem)]
    (let [firstChild (gdom/getFirstElementChild el)]
      (if firstChild
        (before firstChild neue)
        (append el neue)))))

(defn replace [elem neue]
  (doseq [el (->coll elem)]
    (after el neue)
    (unappend el)))

(defn empty [elem]
  (doseq [el (->coll elem)]
    (gdom/removeChildren el)))

;; incremental dom
;; from https://github.com/christoph-frick/cljs-incremental-dom/blob/master/src/incdom/core.cljs

(def ^:private all-dot-re (js/RegExp. "\\." "g"))

(defn- bench
  [fn]
  (let [start (.now js/performance)
        result (fn)
        end (.now js/performance)]
    (.info js/console (str "Took " (- end start) "ms"))
    result))

(defn- extract-classes
  "Extract tag and optional classes out of a keyword in the form :tag.cls1.cls2"
  [elem]
  (let [[tn & cls] (string/split (name elem) ".")]
    [tn (conj {} (when (seq? cls) [:class (string/join " " cls)]))]))

(defn- convert-attr-name
  "Coerce an attribute name into a string"
  [attr-name]
  (cond
    (keyword? attr-name) (name attr-name)
    :else (str attr-name)))

(defn- convert-attr-value
  "Coerce an attribute value into a representation incdom allows to use"
  [attr-value]
  (cond
    (map? attr-value) (clj->js attr-value)
    (fn? attr-value) attr-value
    :else (str attr-value)))

(defn- attr
  "Render an attribute via incdom"
  [attr-name attr-value]
  (incd/attr
   (convert-attr-name attr-name)
   (convert-attr-value attr-value)))

(defn- element-open
  "Render an hiccup style opening tag via incdom"
  [elem attrs]
  (let [[tag-name class-map] (extract-classes elem)
        attrs (merge-with #(str %1 " " %2) attrs class-map)]
    (incd/elementOpenStart tag-name (:key attrs) nil)
    (run! (partial apply attr) attrs)
    (incd/elementOpenEnd tag-name)))

(defn- element-close
  "Render a closing tag via incdom"
  [elem]
  (let [[tag-name class-map] (extract-classes elem)]
    (incd/elementClose tag-name)))

(defn- element-void
  "Render an empty tag via incdom"
  [elem attrs]
  (do
    (element-open elem attrs)
    (element-close elem)))

(defn- text
  "Render an text node via incdom"
  [txt]
  (incd/text (str txt)))

(defn patch
  "Apply a function, that calls incdom dom manipulations, to a root dom node"
  [root fn state]
  (incd/patch root fn state))

                                        ; this might not even be close to the capabilities of hiccup
(defn hiccup->incremental-dom
  "Run incdom manipulation for a hiccup vector"
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
            (vector? r) (hiccup->incremental-dom r)
            (sequential? r) (doseq [rr r] (hiccup->incremental-dom rr))
            :else (text r)))
        (element-close elem)))))

;;; for live testing

(defonce state (atom ()))

(defn render! []
  (bench
   #(patch (.getElementById js/document "app")
           (fn [state]
             (hiccup->incremental-dom
              [:div.main
               [:div "Items"]
               [:div.row
                [:div.bolder {:rel-data "test" :class "bold"}
                 [:label "A Label" " " (count state)]]
                (into
                 [:div {:class "state"}]
                 (for [[i d] (zipmap (range) state)]
                   [:div
                    {:key i
                     :style {:transition-property "transform"
                             :transition-duration "500ms"
                             :font-weight "bold"}}
                    (str d)]))]]))
           @state)))

;; TODO: add id support for hiccup syntax
;; TODO: ability to trigger other events in rf?

(defn result-fn []
  (let [result (volatile! nil)]
    (fn
      ([] @result)
      ([acc] acc)
      ([acc x] (vreset! result x) acc))))

(defn- bench
  [fn]
  (let [start (.now js/performance)
        result (fn)
        end (.now js/performance)]
    (.info js/console (str "Took " (- end start) "ms"))
    result))

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
              (fn [state]
                (hiccup->incremental-dom hiccup))
              state)
       (rf acc x)))))

(defn register! [src type rf x]
  (let [xrf (rf (result-fn))
        acc nil]
    (event/listen src
                  type
                  (fn [e]
                    (xrf acc (assoc x
                                    :context/rf rf
                                    :context/x x
                                    :event/target (.-target e)
                                    :event/type (.-type e)
                                    :event/src (.-currentTarget e)
                                    :event/event e))))))

#_(
   (register!
    (gdom/getElement "app")
    :click
    (comp
     (bench-rf
      (comp

       (fn [rf]
         (let [vstate (volatile! nil)]
           (fn
             ([] (rf))
             ([acc] (rf acc))
             ([acc {:event/keys [src target type]
                    :component/keys [state]
                    :as x}]
              (when-not @vstate
                (vreset! vstate state))
              (->> @vstate
                   (cycle)
                   (drop 1)
                   (take (count @vstate))
                   (vreset! vstate))
              (->> (assoc x :component/state @vstate)
                   (rf acc))))))
       (map (fn [{:component/keys [state] :as x}]
              (assoc x :dom/hiccup [:div.main
                                    [:div.row
                                     (into
                                      [:div {:class "state"}]
                                      (for [[i d] (zipmap (range) state)]
                                        [:div
                                         {:key i
                                          :style {:transition-property "transform"
                                                  :transition-duration "500ms"
                                                  :font-weight "bold"}}
                                         (str d)]))]])))
       render-rf))
     (map (fn [{:event/keys [target type]
                :perf/keys [start end]
                :as x}]
            (.info js/console (str (- end start) "ms"))
            x)))
    {:component/state (range 10)})

   (goog.events/removeAll
    (gdom/getElement "app"))
   )

#_(

   (hiccup->incremental-dom
    [:div])

   (render!)
   (add-watch state :render render!)
   (remove-watch state :render)

   (->> (range 20) (map (fn [i] (swap! state conj i))) (doall))

   (->> @state
        (cycle)
        (drop 1)
        (take (count @state))
        (reset! state))
   (def a
     (js/setInterval
      (fn [_]
        (let [head (first @state)
              tail (rest @state)]
          (->> (concat tail [head])
               (reset! state))))
      1000))
   (js/clearInterval a)

   (reset! state ())
   (swap! state conj (js/Date.))
   )

#_(



   )


#_(

   (ns jaq.http.xrf.client)
   (require 'jaq.http.xrf.client)

   (normalize-element [:p "foo"])


   (gdom/getElement "app")

   (-> (gdom/getElement "main")
       (replace (html [:div#main
                       [:h1 "hello"]
                       [:p "this is a list"]
                       [:ul
                        (for [i (range 10)]
                          [:li (str i)])]])))

   (goog.ui.Zippy. (html [:div]) (html [:p]))

   (let [header (dom/element "div")
         content (dom/element "p")]
     (goog.ui.Zippy. "foo" content))

   (html [:div
          [:ul
           (for [i (range 10)]
             [:li i])]])

   (let [doc (dom/get-element "app")
         ;;id (events/listen doc :mouseenter (fn [e] (.log js/console e)))
         ]
     #_(->> (range 10)
            (map (fn [i]
                   (events/unlisten-by-key i)))
            (doall))
     (goog.events/removeAll doc)
     #_(pr-str doc)
     #_(pr-str (events/event-types doc))
     #_(pr-str ::id (.-key id)))



   (+ 1 1)


   )
