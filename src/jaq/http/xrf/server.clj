(ns jaq.http.xrf.server
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [garden.core :refer [css]]
   [hiccup.core :refer [html]]
   [hiccup.page :as page]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.websocket :as websocket]
   [jaq.repl :as r]
   [net.cgrand.xforms :as x]))

#_(defn server-rf [xf]
  (comp
   (map (fn [x]
          (let [shutdown (volatile! nil)]
            (assoc x
                   :context/shutdown shutdown
                   :context/shutdown! (fn []
                                        (-> @shutdown (apply [])))))))
   nio/selector-rf
   (nio/thread-rf
    (comp
     nio/bind-rf
     (nio/accept-rf xf)
     nio/select-rf
     nio/close-rf))))

(declare root)

(def repl-rf
  (comp
   (map (fn [x]
          (let [shutdown (volatile! nil)]
            (assoc x
                   :context/shutdown shutdown
                   :context/shutdown! (fn []
                                        (-> @shutdown (apply [])))))))
   (nio/thread-rf
    (comp
     nio/selector-rf
     (nio/select-rf
      (comp
       (nio/bind-rf
        (comp
         (rf/once-rf (fn [{:context/keys [shutdown]
                           :nio/keys [selector server-channel selection-key] :as x}]
                       (vreset! shutdown (fn []
                                           (prn ::shutting ::down x)
                                           (doseq [sk (.keys selector)]
                                             (-> sk (.channel) (.close))
                                             (-> sk (.cancel)))
                                           (.wakeup selector)
                                           selector))
                       x))
         (nio/accept-rf
          (comp
           nio/valid-rf
           nio/read-rf
           nio/write-rf
           (rf/repeatedly-rf
            (comp
             (nio/receive-rf
              (comp
               (rf/one-rf
                :http/request
                (comp
                 (map (fn [{:keys [byte] :as x}]
                        (assoc x :char (char byte))))
                 header/request-line
                 header/headers))
               (map (fn [{{:keys [headers status path method]} :http/request
                          :as x}]
                      (assoc x
                             :method method
                             :path path
                             :headers headers
                             :status status)))
               (rf/choose-rf
                :path
                {"/repl" (comp
                          (map (fn [{:keys [byte] :as x}]
                                 (assoc x :char (char byte))))
                          (drop 1)
                          params/body
                          (rf/branch (fn [{:keys [method]
                                           {:keys [content-type]} :headers
                                           {input :form session-id :device-id :keys [repl-token]} :params}]
                                       (and
                                        (= content-type "application/x-www-form-urlencoded")
                                        (= method :POST)
                                        (= repl-token (or #_(:JAQ-REPL-TOKEN env) "foobarbaz"))))
                                     (comp
                                      (map (fn [{{input :form session-id :device-id :keys [repl-token]} :params
                                                 :keys [headers] :as x}]
                                             (->> {:input input :session-id session-id}
                                                  (jaq.repl/session-repl)
                                                  ((fn [{:keys [val ns ms]}]
                                                     (assoc x
                                                            :http/status 200
                                                            :http/reason "OK"
                                                            :http/headers {:content-type "text/plain"
                                                                           :connection "keep-alive"}
                                                            :http/body (str ns " => " val " - " ms "ms" "\n"))))))))
                                     (comp
                                      (map (fn [{:keys [uuid] :as x}]
                                             (assoc x
                                                    :http/status 403
                                                    :http/reason "Forbidden"
                                                    :http/headers {:content-type "text/plain"
                                                                   :connection "keep-alive"}
                                                    :http/body "Forbidden"))))))
                 "/ws" (comp
                        (map (fn [{{:keys [sec-websocket-key]} :headers
                                   :as x}]
                               (assoc x
                                      :http/status 101
                                      :http/reason "Switching Protocols"
                                      :http/headers {:upgrade "websocket"
                                                     :connection "upgrade"
                                                     :sec-websocket-accept (websocket/handshake sec-websocket-key)}))))
                 "/" (map (fn [{:app/keys [uuid]
                                {:keys [x-appengine-city
                                        x-appengine-country
                                        x-appengine-region
                                        x-appengine-user-ip
                                        x-cloud-trace-context]} :headers
                                :as x}]
                            (assoc x
                                   :http/status 200
                                   :http/reason "OK"
                                   :http/headers {:content-type "text/html" #_"text/plain"
                                                  :connection "keep-alive"}
                                   :http/body (root x)
                                   #_(str "You are from " x-appengine-city " in "
                                                   x-appengine-region " / " x-appengine-country "."
                                                   " Your IP is " x-appengine-user-ip " and your trace is "
                                                   x-cloud-trace-context "."))))
                 :default (map (fn [{:app/keys [uuid]
                                     {:keys [host]} :headers
                                     :as x}]
                                 (assoc x
                                        :http/status 404
                                        :http/reason "Not Found"
                                        :http/headers {:content-type "text/plain"
                                                       :connection "keep-alive"}
                                        :http/body "NOT FOUND")))})))
             nio/writable-rf
             (nio/send-rf (comp
                           nio/response-rf))
             nio/readable-rf
                       ;; remember request
                       (rf/one-rf :http/request (map :http/request))
                       (map (fn [{:http/keys [request]
                                  {:keys [path]} :http/request
                                  :as x}]
                              (assoc x :path path)))
                       ;; sink for websocket
                       (rf/choose-rf :path {"/ws" (comp
                                                   (nio/receive-rf
                                                    (comp
                                                     websocket/decode-frame-rf
                                                     websocket/decode-message-rf
                                                     (fn [rf]
                                                       (let [once (volatile! false)]
                                                         (fn
                                                           ([] (rf))
                                                           ([acc] (rf acc))
                                                           ([acc {:nio/keys [selection-key]
                                                                  :context/keys [ws]
                                                                  :ws/keys [message op frames]
                                                                  :as x}]
                                                            #_(prn ::frame frame)
                                                            (prn ::message message)
                                                            (vswap! ws conj {:op op
                                                                             :message message})
                                                            #_(vswap! ws conj frame)
                                                            acc)))))))})))))))))
     nio/close-rf))))

(defn root [{:keys [headers]
             {:keys [x-appengine-city
                     x-appengine-country
                     x-appengine-region
                     x-appengine-user-ip
                     x-cloud-trace-context]} :headers
             :as x}]
  (page/html5
   [:head [:style {:type "text/css"}
           (css [:body {:font-size "16px"}]
                [:h1 {:font-size "24px"}])]]
   [:body
    [:h1 "Information"]
    [:p "You are from " x-appengine-city " in "
     x-appengine-region " / " x-appengine-country "."
     " Your IP is " x-appengine-user-ip " and your trace is "
     x-cloud-trace-context "."]
    #_[:div
     [:h5 "Debug:"]
     [:pre (with-out-str (clojure.pprint/pprint x))]]]))

#_(

   (with-out-str (clojure.pprint/pprint {:foo :bar}))
   (page/html5
    [:head [:style {:type "text/css"}
            (css [:body {:font-size "16px"}]
                 [:h1 {:font-size "24px"}])]]
    [:body [:h1 "Foo bar"]])

   (ifn? root)
   (root)

   )

#_(
   *ns*
   *e
   (in-ns 'jaq.http.xrf.server)
   (require 'clojure.pprint)

   (def x
     (->> [{:context/bip-size (* 1 4096)
            :http/host "localhost"
            :http/scheme :http
            :http/port 10010
            :http/minor 1 :http/major 1}]
          (into [] repl-rf)
          (first)))
   (-> x :context/shutdown! (apply []))

   )
