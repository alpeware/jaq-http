(ns jaq.http.xrf.handler
  #?(:cljs
     (:require [cljs.core]
               [clojure.pprint :refer [pprint]]
               [goog.dom :as dom]
               [jaq.http.xrf.html :as html])
     :clj
     (:require [clojure.pprint :refer [pprint]]
               [jaq.http.xrf.rf :as rf]
               [jaq.http.xrf.nio :as nio]
               [jaq.http.xrf.repl :refer [send-response-rf]]
               [jaq.http.xrf.ssl :as ssl]
               [jaq.http.xrf.http :as http]
               [jaq.gcp.appengine :as appengine]
               [jaq.gcp.storage :as storage]))
  #?(:cljs
     (:import [goog.net XhrIo])))

(def echo-rf
  (comp
   (comp
    #?(:cljs
       (comp
        html/render-rf
        (map (fn [x]
               ;; clean up event handler
               (some-> (dom/getDocument)
                       (.querySelector "button")
                       (goog.events/removeAll))
               x))
        (fn [rf] ;; should come from NetManager pool
          (let [xhr (volatile! nil)]
            (fn
              ([] (rf))
              ([acc] (rf acc))
              ([acc {:event/keys [src target type event]
                     :component/keys [state]
                     :as x}]
               (when-not @xhr
                 (vreset! xhr (XhrIo.)))
               (->> (assoc x :net/xhr @xhr)
                    (rf acc))))))
        ;; form handler
        (html/listen-rf
         (dom/getElement "submit")
         :click
         (comp
          (comp
           (fn [rf]
             (let [vstate (volatile! nil)]
               (fn
                 ([] (rf))
                 ([acc] (rf acc))
                 ([acc {:event/keys [src target type event]
                        :component/keys [state]
                        :as x}]
                  (.preventDefault event)
                  (rf acc x)))))
           (map (fn [{:component/keys [state]
                      :event/keys [src target type event]
                      :as x}]
                  (.info js/console (pr-str @state))
                  (assoc x
                         :event/src (dom/getElement "info")
                         :dom/hiccup [:div
                                      [:label "Token entered: " (:token @state)]])))
           html/render-rf)
          ;; trigger server request
          (comp
           (map (fn [{:net/keys [xhr]
                      :component/keys [state]
                      :as x}]
                  (assoc x
                         :net/uri (str "http://localhost:32768/remote?ns=jaq.http.xrf.handler&var=echo-rf&token=" (:token @state))
                         :event/src xhr
                         :event/type (get html/net-events :complete))))
           (map (fn [{:net/keys [xhr uri]
                      :event/keys [type]
                      :as x}]
                  (.info js/console "requesting " uri " " type)
                  (.send xhr uri)
                  x))))))
       :clj
       (comp rf/identity-rf)))

   ;; this should be on the server
   (comp
    #?(:cljs
       (comp
        (map (fn [x]
               (.info js/console x)
               x))
        html/identity-rf)

       ;; server handler
       :clj
       (comp ;; list files in bucket
        ;; store client connection
        (rf/one-rf :context/client (comp
                                    (map :nio/selection-key)))
        nio/auth-chan
        (drop-while (fn [{:oauth2/keys [expires-in]}]
                      (and (not expires-in)
                           (> (System/currentTimeMillis) expires-in))))
        (rf/one-rf :oauth2/access-token (comp
                                         (map :oauth2/access-token)))
        (map (fn [x]
               (-> x
                   (dissoc :http/json :http/body :http/chunks :http/headers :ssl/engine)
                   (assoc :http/params {:bucket "staging.alpeware-foo-bar.appspot.com"
                                        ;;:prefix "app/v7/classes/jaq/repl"
                                        }
                          :http/host storage/root
                          ;;:storage/prefix "app/v7"
                          ;;:appengine/id (str (System/currentTimeMillis))
                          ;;:appengine/app "alpeware-foo-bar"
                          ;;:appengine/service :default
                          ;;:storage/bucket "staging.alpeware-foo-bar.appspot.com"
                          ))))
        (rf/one-rf
         :storage/pages
         (comp
          (nio/channel-rf
           (comp
            nio/ssl-connection
            (storage/pages-rf
             (comp
              storage/list-objects-rf
              storage/rest-service-rf
              (ssl/request-ssl-rf http/http-rf)
              (ssl/receive-ssl-rf nio/json-response)))
            (map (fn [{:storage/keys [pages]
                       {:keys [items]} :http/json
                       :as x}]
                   #_(prn ::pages pages)
                   (prn ::items (count items))
                   x))
            (drop-while (fn [{:storage/keys [pages]
                              {:keys [nextPageToken items]} :http/json
                              :as x}]
                          nextPageToken))
            (map (fn [{:storage/keys [pages]
                       {:keys [items]} :http/json
                       :as x}]
                   (prn ::pages (count pages) (count items))
                   x))
            (map (fn [{:http/keys [chunks body json]
                       :nio/keys [selection-key selector]
                       :keys [headers]
                       :as x}]
                   ;; clean up channel
                   (prn ::cleanup selection-key)
                   (-> selection-key (.channel) (.close))
                   (.cancel selection-key)
                   #_(.wakeup selector)
                   x))
            #_nio/close-connection))
          (drop-while (fn [{:storage/keys [pages]
                            :nio/keys [selection-key]
                            :as x}]
                        (prn ::pages ::waiting (nil? pages) selection-key)
                        (nil? pages)))
          (rf/one-rf :storage/pages (map :storage/pages))
          (rf/once-rf (fn [{:context/keys [client]
                            :nio/keys [selector selection-key]
                            :storage/keys [pages]
                            :as x}]
                        (nio/writable! client)
                        x))
          (map :storage/pages)))
        ;; got list of files
        (fn [rf]
          (let [objects (volatile! nil)]
            (fn
              ([] (rf))
              ([acc] (rf acc))
              ([acc {:appengine/keys [app service]
                     :storage/keys [pages bucket]
                     :as x}]
               (when-not @objects
                 (->> pages (mapcat :items) (vreset! objects)))
               (prn ::objects (count @objects))
               (-> x
                   (dissoc :http/params :http/headers :http/body
                           :http/req :http/chunks :http/json
                           :ssl/engine)
                   #_(assoc-in [:http/params :app] app)
                   #_(assoc-in [:http/params :service] service)
                   (assoc :storage/objects @objects)
                   #_(assoc :http/host appengine/root-url)
                   (->> (rf acc)))))))
        (map (fn [{{:keys [token]} :params
                   :storage/keys [objects]
                   :as x}]
               (prn ::token token)
               (assoc x
                      :http/status 200
                      :http/reason "OK"
                      :http/headers {:content-type "text/plain"
                                     :connection "keep-alive"}
                      :http/body (with-out-str (pprint objects)))))
        (comp
         nio/writable-rf
         (nio/send-rf (comp
                       nio/response-rf))
         nio/readable-rf)
        (map (fn [x]
               (prn ::sent)
               x)))))

   ;; back on the client
   (comp
    #?(:cljs
       (comp
        ;; register xhr response
        (map (fn [{:net/keys [xhr]
                   :as x}]
               (.info js/console xhr)
               (assoc x
                      :event/src xhr
                      :event/type (get html/net-events :complete))))
        (html/register-rf (comp
                           (map (fn [{:event/keys [target] :as x}]
                                  (assoc x
                                         :net/text (some-> target (.getResponseText)))))
                           (map (fn [{:component/keys [state]
                                      :net/keys [text]
                                      :as x}]
                                  (.info js/console "text" text)
                                  (assoc x
                                         :event/src (dom/getElement "response")
                                         :dom/hiccup [:div
                                                      [:label "Server response: "]
                                                      [:pre text]])))
                           html/render-rf)))
       :clj
       (comp rf/identity-rf)))))

#_(

   *e
   *ns*
   (require 'jaq.http.xrf.handler :reload)
   (in-ns 'jaq.http.xrf.handler)

   (-> y :nio/selection-key)
   (with-out-str (pprint {:foo :bar}))
   ;; init
   (into []
         (comp
          html/render-rf)
         [{:event/src (dom/getElement "app")
           :dom/hiccup [:div#main
                        [:form
                         [:label "Token"]
                         [:input {:type "text"
                                  :value ""}]
                         [:button#submit {:type "button"} "Submit"]]
                        [:div#info]
                        [:div#response]]}])

   (def x
     (let [state (volatile! {:token ""})
           on-change (fn [k e] (vswap! state assoc k (-> e .-target .-value)))
           on-focus (fn [k e] (-> e .-target .-value (set! (get @state k))))
           x {:component/state state
              :event/src (dom/getElement "app")
              :dom/hiccup [:div#main
                           [:form
                            [:label "Token"]
                            [:input {:type "text"
                                     :value (:token @state)
                                     :onfocus (partial on-focus :token)
                                     :onchange (partial on-change :token)}]
                            [:button#submit {:type "button"} "Submit"]]
                           [:div#info]
                           [:div#response]]}]
       (first
        (into [] echo-rf [x]))))

   (-> (dom/getDocument) (.querySelector "button") (goog.events/removeAll))

   )
