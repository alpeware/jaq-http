(ns jaq.http.xrf.client
  (:require
   [goog.dom :as dom]
   [incremental-dom :as incd]
   [clojure.string :as string]
   [cljs.core]
   ;;[cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
   ;;[cljs.pprint :refer [pprint] :refer-macros [pp]]
   [clojure.browser.event :as event]
   [jaq.http.xrf.html :as html]))


#_(

   (init)
   (def input (volatile! ""))
   (vreset! input "")
   @input

   (range 10)

   (into [] (comp
             (map inc)
             #?(:cljs (take 1)
                :clj (take 10)))
         (range 20))

   (require 'cljs.core)
   #?(:cljs :foo :clj :clj)

   (register!
    (gdom/getElement "state")
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
       (map (fn [{:component/keys [state input]
                  :as x}]
              (assoc x :dom/hiccup (into
                                    [:div {:class "state"}]
                                    (for [i state]
                                      [:div {:key i}
                                       (str i)])))))
       render-rf))
     (map (fn [{:event/keys [target type]
                :perf/keys [start end]
                :as x}]
            (.info js/console (str (- end start) "ms"))
            x)))
    {:component/state (range 10)
     :component/input input})

   (goog.events/removeAll
    (gdom/getElement "state"))

   (register!
    (gdom/getElement "in")
    :keydown
    (comp
     (bench-rf
      (comp
       (fn [rf]
         (let [vstate (volatile! nil)]
           (fn
             ([] (rf))
             ([acc] (rf acc))
             ([acc {:event/keys [src target type event]
                    :component/keys [input]
                    :as x}]
              (.preventDefault event)
              (vswap! input str (.-key event))
              (rf acc x)))))
       (map (fn [{:component/keys [state input]
                  :event/keys [src target type event]
                  :as x}]
              (.info js/console event (js->clj event :keywordize-keys true))
              (assoc x :dom/hiccup
                     [:div
                      [:label "Event " event]
                      [:input {:type "text" :value @input}]])))
       render-rf))
     (map (fn [{:event/keys [target type]
                :perf/keys [start end]
                :as x}]
            (.info js/console (str (- end start) "ms"))
            x)))
    {:component/state (range 10)
     :component/input input})



   (goog.events/removeAll
    (gdom/getElement "in"))

   (defn change [e]
     (vreset! input (-> e .-target .-value)))

   (register!
    (gdom/getElement "app")
    :click
    (comp
     (bench-rf
      (comp
       #_(fn [rf]
           (let [vstate (volatile! nil)]
             (fn
               ([] (rf))
               ([acc] (rf acc))
               ([acc {:event/keys [src target type event]
                      :component/keys [input]
                      :as x}]
                #_(.preventDefault event)
                #_(vswap! input str (.-key event))
                (rf acc x)))))
       (map (fn [{:component/keys [state input]
                  :event/keys [src target type event]
                  :as x}]
              (.info js/console event #_(js->clj event :keywordize-keys true))
              (assoc x :dom/hiccup
                     [:div
                      [:label "Type "]
                      [:input {:type "text" :value @input
                               :key "key"
                               :onchange (fn [e] (vreset! input (-> e .-target .-value)))}]])))
       render-rf))
     (map (fn [{:event/keys [target type]
                :perf/keys [start end]
                :as x}]
            (.info js/console (str (- end start) "ms"))
            x)))
    {:component/state (range 10)
     :component/input input})

   (vreset! input "foo")

   @input

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

   (in-ns 'jaq.http.xrf.client)
   (reset! jaq.http.xrf.browser/cljs-ns 'jaq.http.xrf.client)

   *ns*
   *e
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
