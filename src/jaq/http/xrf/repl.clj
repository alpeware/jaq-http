(ns jaq.http.xrf.repl
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [garden.core :refer [css]]
   [hiccup.core :refer [html]]
   [hiccup.page :as page]
   [jaq.gcp.storage :as storage]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.websocket :as websocket]
   [jaq.http.xrf.browser :as browser]
   [jaq.repl :as r]
   [net.cgrand.xforms :as x])
  (:import
   [java.nio.file NoSuchFileException]))

(declare root)

#_(def repl-rf
    (comp
     nio/selector-rf
     (map (fn [x]
            (let [shutdown (volatile! nil)]
              (assoc x
                     :context/shutdown shutdown
                     :context/shutdown! (fn []
                                          (-> @shutdown (apply [])))))))
     (nio/thread-rf
      (comp
       (nio/select-rf
        (comp
         (nio/bind-rf
          (comp
           (rf/once-rf (fn [{:context/keys [shutdown]
                             :nio/keys [selector server-channel selection-key] :as x}]
                         (prn ::registering)
                         (vreset! shutdown (fn []
                                             (prn ::shutting ::down x)
                                             (doseq [sk (.keys selector)]
                                               (-> sk (.channel) (.close))
                                               (-> sk (.cancel)))
                                             (.wakeup selector)
                                             selector))
                         x))
           browser/env-rf
           (nio/accept-rf
            (comp
             ;;
             (rf/repeatedly-rf
              (comp
               nio/valid-rf
               nio/read-rf
               nio/write-rf
               (nio/receive-rf
                (comp
                 (rf/one-rf
                  :http/request
                  (comp
                   (map (fn [{:keys [byte] :as x}]
                          (assoc x :char (char byte))))
                   header/request-line
                   header/headers
                   (map (fn [{:keys [path] :as x}]
                          (prn ::one ::request path)
                          x))))
                 (map (fn [{{:keys [headers status path method params]} :http/request
                            :as x}]
                        (assoc x
                               :method method
                               :path path
                               :params params
                               :headers headers
                               :status status)))
                 (rf/choose-rf
                  (fn [{:keys [path params]}]
                    (str "/"
                         (some-> path (string/split #"/") (second))))
                  {"/repl" (comp
                            (rf/choose-rf
                             :path
                             {"/repl" (comp
                                       (map (fn [{:keys [byte] :as x}]
                                              (assoc x :char (char byte))))
                                       (drop 1)
                                       params/body
                                       (rf/choose-rf
                                        (fn [{:keys [method]
                                              {:keys [content-type]} :headers
                                              {input :form session-id :device-id :keys [repl-token repl-type]} :params}]
                                          [content-type method repl-type repl-token])
                                        {["application/x-www-form-urlencoded" :POST ":clj" "foobarbaz"]
                                         (comp
                                          (map (fn [{{input :form session-id :device-id :keys [repl-token] :as params} :params
                                                     :keys [headers] :as x}]
                                                 (->> {:input input :session-id session-id}
                                                      (jaq.repl/session-repl)
                                                      ((fn [{:keys [val ns ms]}]
                                                         (assoc x
                                                                :params params
                                                                :http/status 200
                                                                :http/reason "OK"
                                                                :http/headers {:content-type "text/plain"
                                                                               :connection "keep-alive"}
                                                                :http/body (str ns " => " val " - " ms "ms" "\n"))))))))
                                         ["application/x-www-form-urlencoded" :POST ":cljs" "foobarbaz"]
                                         (comp
                                          (map (fn [{{input :form session-id :device-id :keys [repl-token] :as params} :params
                                                     :keys [headers] :as x}]
                                                 (prn ::input input params)
                                                 (assoc x
                                                        :params params
                                                        :http/status 200
                                                        :http/reason "OK"
                                                        :http/headers {:content-type "text/plain"
                                                                       :connection "keep-alive"}))))
                                         :default (comp
                                                   (map (fn [{:keys [uuid] :as x}]
                                                          (assoc x
                                                                 :http/status 403
                                                                 :http/reason "FORBIDDEN"
                                                                 :http/headers {:content-type "text/plain"
                                                                                :connection "keep-alive"}
                                                                 :http/body "Forbidden"))))}))
                              "/repl/ws" (comp
                                          (map (fn [{:context/keys [repl-clients]
                                                     :nio/keys [selection-key]
                                                     {:keys [sec-websocket-key]} :headers
                                                     {:keys [id]} :params
                                                     :as x}]
                                                 (prn ::new ::repl id selection-key)
                                                 (vswap! repl-clients assoc id selection-key)
                                                 (assoc x
                                                        :http/status 101
                                                        :http/reason "Switching Protocols"
                                                        :http/headers {:upgrade "websocket"
                                                                       :connection "upgrade"
                                                                       :sec-websocket-accept (websocket/handshake sec-websocket-key)}))))}))
                   "/out" (comp
                           (map (fn [{:keys [path] :as x}]
                                  (assoc x :file/path (str "." path))))
                           (rf/catch-rf
                            NoSuchFileException
                            (fn [x] (assoc x :file/size 0))
                            (comp
                             storage/file-rf
                             storage/open-rf
                             storage/read-rf
                             storage/flip-rf
                             storage/close-rf))
                           (rf/branch (fn [{:file/keys [size]}]
                                        (some-> size (> 0)))
                                      (map (fn [{:keys [path]
                                                 :file/keys [^ByteBuffer buf content-type]
                                                 :as x}]
                                             (assoc x
                                                    :http/status 200
                                                    :http/reason "OK"
                                                    :http/headers {:content-type content-type
                                                                   :connection "keep-alive"}
                                                    :http/body buf)))
                                      (map (fn [{:keys [path]
                                                 :as x}]
                                             (assoc x
                                                    :http/status 404
                                                    :http/reason "Not Found"
                                                    :http/headers {:content-type "text/plain"
                                                                   :connection "keep-alive"}
                                                    :http/body (str "Not found: " path))))))
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
                                     :http/headers {:content-type "text/html"
                                                    :connection "keep-alive"}
                                     :http/body (root x))))
                   :default (map (fn [{:keys [path]
                                       {:keys [host]} :headers
                                       :as x}]
                                   (assoc x
                                          :http/status 404
                                          :http/reason "Not Found"
                                          :http/headers {:content-type "text/plain"
                                                         :connection "keep-alive"}
                                          :http/body (str "NOT FOUND " path " @ " host))))})))
               ;; remember request
               (rf/one-rf :http/request (comp
                                         (map (fn [{:keys [params] :as x}]
                                                (prn ::one params)
                                                (assoc-in x [:http/request :params] params)))
                                         (map :http/request)))
               (map (fn [{:http/keys [request]
                          :nio/keys [selection-key]
                          {:keys [path params]} :http/request
                          :as x}]
                      (prn path params selection-key)
                      (assoc x :path path :params params)))
               ;; send response
               (rf/choose-rf
                (fn [{:keys [path]
                      {:keys [repl-type]} :params
                      :as x}]
                  [path repl-type])
                {["/repl" ":cljs"] (rf/branch (fn [{:context/keys [repl-clients]
                                                    {input :form id :device-id :keys [repl-token]} :params
                                                    :as x}]
                                                (get @repl-clients id))
                                              (comp ;; found session
                                               (fn [rf]
                                                 (let [start (volatile! nil)]
                                                   (fn
                                                     ([] (rf))
                                                     ([acc] (rf acc))
                                                     ([acc {:context/keys [callback-rf callback-x]
                                                            :nio/keys [selection-key]
                                                            :ws/keys [message]
                                                            :as x}]
                                                      (when-not @start
                                                        (vreset! start (System/nanoTime)))
                                                      (rf acc (assoc x :repl/start @start))))))
                                               (map (fn [{:context/keys [repl-clients]
                                                          :nio/keys [selection-key]
                                                          {input :form id :device-id :keys [repl-token]} :params
                                                          :keys [headers] :as x}]
                                                      (prn ::input input selection-key)
                                                      (let [sk (get @repl-clients id)]
                                                        (assoc x
                                                               :repl/client sk
                                                               :repl/input input
                                                               :repl/id id))))
                                               ;; TODO: only run once?
                                               browser/compile-rf
                                               ;; send to ws channel
                                               (fn [rf]
                                                 (let [once (volatile! false)
                                                       msg (volatile! nil)
                                                       xf (comp
                                                           nio/write-rf
                                                           nio/read-rf
                                                           (nio/send-rf
                                                            (comp
                                                             websocket/encode-message-rf
                                                             websocket/encode-frame-rf))
                                                           (nio/receive-rf
                                                            (comp
                                                             websocket/decode-frame-rf
                                                             websocket/decode-message-rf))
                                                           (fn [rf]
                                                             (let [once (volatile! nil)]
                                                               (fn
                                                                 ([] (rf))
                                                                 ([acc] (rf acc))
                                                                 ([acc {:context/keys [callback-rf callback-x]
                                                                        :nio/keys [selection-key]
                                                                        :ws/keys [message]
                                                                        :as x}]
                                                                  (when-not @once
                                                                    (do
                                                                      (prn ::message message)
                                                                      ;; park
                                                                      (.interestOps selection-key 0)
                                                                      (-> callback-x :nio/selection-key (nio/writable!))
                                                                      (vreset! once true)
                                                                      (vreset! msg message)
                                                                      #_(callback-rf acc (assoc callback-x
                                                                                                :ws/message message))))
                                                                  (rf acc x))))))
                                                       xrf (xf (rf/result-fn))]
                                                   (fn
                                                     ([] (rf))
                                                     ([acc] (rf acc))
                                                     ([acc {:nio/keys [selection-key in out selector]
                                                            original-rf :context/rf
                                                            original-x :context/x
                                                            :repl/keys [client js
                                                                        input id]
                                                            :as x}]
                                                      (let [{client-x :context/x
                                                             :as client-attachment} (.attachment client)
                                                            client-x (assoc client-x
                                                                            :context/callback-rf rf
                                                                            :context/callback-x x
                                                                            :ws/message (j/write-str {:form js})
                                                                            :ws/op :text)]
                                                        (when-not @once
                                                          (->> (assoc client-attachment
                                                                      :context/rf xrf
                                                                      :context/x client-x)
                                                               (.attach client))
                                                          (xrf acc client-x)
                                                          (prn ::ws ::started)
                                                          (vreset! once true))
                                                        (cond
                                                          ;; waiting to send response
                                                          (xrf)
                                                          (let [{:ws/keys [message]} (xrf)]
                                                            (rf acc (assoc x :ws/message message)))

                                                          :else
                                                          (do
                                                            (prn ::waiting)
                                                            acc)))))))
                                               (comp
                                                (map (fn [{:repl/keys [start]
                                                           :as x}]
                                                       (assoc x :repl/ms (quot (- (System/nanoTime) start) 1000000))))
                                                (map (fn [{:ws/keys [message]
                                                           :repl/keys [cljs-ns ms]
                                                           :as x}]
                                                       (prn ::response message)
                                                       (let [{:keys [val]} (j/read-str message :key-fn keyword)]
                                                         (assoc x
                                                                :http/status 200
                                                                :http/reason "OK"
                                                                :http/headers {:content-type "text/plain"
                                                                               :connection "keep-alive"}
                                                                :http/body (str cljs-ns " => " val " - " ms "ms" "\n")))))
                                                (map (fn [x]
                                                       (def y x)
                                                       x))
                                                #_(rf/debug-rf ::send)
                                                (nio/send-rf (comp
                                                              nio/response-rf))
                                                nio/readable-rf))
                                              (comp ;; no session
                                               (map (fn [{:context/keys [repl-clients]
                                                          {input :form id :device-id :keys [repl-token]} :params
                                                          :keys [headers] :as x}]
                                                      (assoc x
                                                             :http/body (str "No active session for " id))))
                                               nio/writable-rf
                                               (nio/send-rf (comp
                                                             nio/response-rf))))
                 ["/repl/ws" nil] (comp
                                   nio/writable-rf
                                   (nio/send-rf (comp
                                                 nio/response-rf))
                                   nio/readable-rf
                                   (nio/receive-rf
                                    (comp
                                     websocket/decode-frame-rf
                                     websocket/decode-message-rf
                                     (rf/repeatedly-rf
                                      (nio/send-rf
                                       (comp
                                        websocket/encode-message-rf
                                        websocket/encode-frame-rf)))
                                     (fn [rf]
                                       (let [once (volatile! false)]
                                         (fn
                                           ([] (rf))
                                           ([acc] (rf acc))
                                           ([acc {:nio/keys [selection-key]
                                                  :context/keys [ws]
                                                  :ws/keys [message op frames]
                                                  :as x}]
                                            (prn ::message op)
                                            acc)))))))
                 :default (comp
                           #_(map (fn [{:nio/keys [selection-key]
                                        :http/keys [body]
                                        :as x}]
                                    (prn ::default selection-key)
                                    (prn ::body body)
                                    x))
                           (comp
                            nio/writable-rf
                            (nio/send-rf (comp
                                          nio/response-rf))
                            nio/readable-rf))})))
             nio/valid-rf
             (map (fn [x] (prn ::repeatedly) x))))))))
       nio/close-rf))))

(defn root [{:keys [headers]
             {:keys [x-appengine-city
                     x-appengine-country
                     x-appengine-region
                     x-appengine-user-ip
                     x-cloud-trace-context]} :headers
             :as x}]
  (page/html5
   [:head
    [:meta {:name "viewport" :content "width=device-width, initial-scale=1"}]
    [:title "CLJS REPL"]
    [:style {:type "text/css"}
     (css [:body {:font-size "16px"}]
          [:h1 {:font-size "24px"}])]]
   [:body
    [:h1 "CLJS REPL"]
    [:div#app]
    [:script
     ;; inits
     "var CLOSURE_UNCOMPILED_DEFINES = {'goog.json.USE_NATIVE_JSON': true};"
     ;; load deps async not using document.write
     "var CLOSURE_DEFINES = {'goog.ENABLE_CHROME_APP_SAFE_SCRIPT_LOADING': true};"
     ;; handle dependency graph ourselves
     "var CLOSURE_NO_DEPS = true;"
     ;; app state?
     "var STATE = {id: 'JAQ-DEVICE-ID'};"]
    (page/include-js "/out/goog/base.js")
    (page/include-js "/out/goog/deps.js")
    (page/include-js "/out/brepl_deps.js")
    ;; load main ns
    [:script "goog.require('goog.json');"]
    [:script "goog.require('cljs.repl');"]
    ;; TODO: add as CLJS
    [:script
     "let evaluate = (s) => {try { return {val: cljs.core.pr_str.call(null, eval(s)), status: 'success'}; } catch(error) { return {val: error.message, status: 'exception'}; }};"
     "let session = (id) => { console.log('starting session...');
          goog.isProvided_ = (e) => false;
          let ws = new WebSocket(document.location.href.replace('http', 'ws') + 'repl/ws?id=' + id);
          ws.onmessage = (e) => ws.send(goog.json.serialize(evaluate(goog.json.parse(e.data).form))); };"
     "window.addEventListener('load', (e) => session(STATE.id));"]]))

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

(def repl-rf
  (comp
   nio/selector-rf
   (map (fn [x]
          (let [shutdown (volatile! nil)]
            (assoc x
                   :context/shutdown shutdown
                   :context/shutdown! (fn []
                                        (-> @shutdown (apply [])))))))
   (nio/thread-rf
    (comp
     (nio/select-rf
      (comp
       (nio/bind-rf
        (comp
         (rf/once-rf (fn [{:context/keys [shutdown]
                           :nio/keys [selector server-channel selection-key] :as x}]
                       (prn ::registering)
                       (vreset! shutdown (fn []
                                           (prn ::shutting ::down x)
                                           (doseq [sk (.keys selector)]
                                             (-> sk (.channel) (.close))
                                             (-> sk (.cancel)))
                                           (.wakeup selector)
                                           selector))
                       x))
         browser/env-rf
         (nio/accept-rf
          (comp
           ;; open connection
           (rf/repeatedly-rf
            (comp
             nio/valid-rf
             nio/read-rf
             nio/write-rf
             ;; parse request line and headers
             (nio/receive-rf
              (comp
               (comp
                (map (fn [{:keys [byte] :as x}]
                       (assoc x :char (char byte))))
                header/request-line
                header/headers
                (map (fn [{:keys [path] :as x}]
                       (prn ::one ::request path)
                       x)))
               #_(rf/one-rf
                  :http/request
                  (comp
                   (map (fn [{:keys [byte] :as x}]
                          (assoc x :char (char byte))))
                   header/request-line
                   header/headers
                   (map (fn [{:keys [path] :as x}]
                          (prn ::one ::request path)
                          x))))))
             ;; normalize
             (rf/one-rf :http/request (comp
                                       rf/identity-rf))
             #_(map (fn [{:http/keys [request]
                          :nio/keys [selection-key]
                          {:keys [path params]} :http/request
                          :as x}]
                      (prn path params selection-key)
                      (assoc x :path path :params params)))
             (map (fn [{{:keys [headers status path method params]} :http/request
                        :as x}]
                    #_(prn ::path path)
                    (assoc x
                           :method method
                           :path path
                           :params params
                           :headers headers
                           :status status)))
             ;; request handlers
             (rf/choose-rf
              (fn [{:keys [path]}]
                (str "/"
                     (some-> path (string/split #"/") (second))))
              {"/repl" (comp
                        (rf/choose-rf
                         :path
                         {"/repl" (comp
                                   ;; parse post body
                                   (nio/receive-rf
                                    (comp
                                     (map (fn [{:keys [byte] :as x}]
                                            (assoc x :char (char byte))))
                                     params/body
                                     (map (fn [{:keys [params] :as x}]
                                            (prn ::one ::params params)
                                            x))))
                                   (rf/one-rf :params (comp
                                                       (map :params)))
                                   (rf/choose-rf
                                    (fn [{:keys [method]
                                          {:keys [content-type]} :headers
                                          {input :form session-id :device-id :keys [repl-token repl-type]} :params}]
                                      [content-type method repl-type repl-token])
                                    {["application/x-www-form-urlencoded" :POST ":clj" "foobarbaz"]
                                     (comp
                                      (map (fn [{{input :form session-id :device-id :keys [repl-token] :as params} :params
                                                 :keys [headers] :as x}]
                                             (->> {:input input :session-id session-id}
                                                  (jaq.repl/session-repl)
                                                  ((fn [{:keys [val ns ms]}]
                                                     (assoc x
                                                            :params params
                                                            :http/status 200
                                                            :http/reason "OK"
                                                            :http/headers {:content-type "text/plain"
                                                                           :connection "keep-alive"}
                                                            :http/body (str ns " => " val " - " ms "ms" "\n")))))))
                                      (comp
                                       nio/writable-rf
                                       (nio/send-rf (comp
                                                     nio/response-rf))
                                       nio/readable-rf))
                                     ["application/x-www-form-urlencoded" :POST ":cljs" "foobarbaz"]
                                     (comp
                                      (map (fn [{{input :form session-id :device-id :keys [repl-token] :as params} :params
                                                 :keys [headers] :as x}]
                                             (prn ::input input params)
                                             (assoc x
                                                    :params params
                                                    :http/status 200
                                                    :http/reason "OK"
                                                    :http/headers {:content-type "text/plain"
                                                                   :connection "keep-alive"})))
                                      (rf/branch (fn [{:context/keys [repl-clients]
                                                       {input :form id :device-id :keys [repl-token]} :params
                                                       :as x}]
                                                   (get @repl-clients id))
                                                 (comp ;; found session
                                                  (fn [rf]
                                                    (let [start (volatile! nil)]
                                                      (fn
                                                        ([] (rf))
                                                        ([acc] (rf acc))
                                                        ([acc {:context/keys [callback-rf callback-x]
                                                               :nio/keys [selection-key]
                                                               :ws/keys [message]
                                                               :as x}]
                                                         (when-not @start
                                                           (vreset! start (System/nanoTime)))
                                                         (rf acc (assoc x :repl/start @start))))))
                                                  (map (fn [{:context/keys [repl-clients]
                                                             :nio/keys [selection-key]
                                                             {input :form id :device-id :keys [repl-token]} :params
                                                             :keys [headers] :as x}]
                                                         (prn ::input input selection-key)
                                                         (let [sk (get @repl-clients id)]
                                                           (assoc x
                                                                  :repl/client sk
                                                                  :repl/input input
                                                                  :repl/id id))))
                                                  ;; TODO: only run once?
                                                  browser/compile-rf
                                                  ;; send to ws channel
                                                  (fn [rf]
                                                    (let [once (volatile! false)
                                                          msg (volatile! nil)
                                                          xf (comp
                                                              nio/write-rf
                                                              nio/read-rf
                                                              (nio/send-rf
                                                               (comp
                                                                websocket/encode-message-rf
                                                                websocket/encode-frame-rf))
                                                              (nio/receive-rf
                                                               (comp
                                                                websocket/decode-frame-rf
                                                                websocket/decode-message-rf))
                                                              (fn [rf]
                                                                (let [once (volatile! nil)]
                                                                  (fn
                                                                    ([] (rf))
                                                                    ([acc] (rf acc))
                                                                    ([acc {:context/keys [callback-rf callback-x]
                                                                           :nio/keys [selection-key]
                                                                           :ws/keys [message]
                                                                           :as x}]
                                                                     (when-not @once
                                                                       (do
                                                                         (prn ::message message)
                                                                         ;; park
                                                                         (.interestOps selection-key 0)
                                                                         (-> callback-x :nio/selection-key (nio/writable!))
                                                                         (vreset! once true)
                                                                         (vreset! msg message)
                                                                         #_(callback-rf acc (assoc callback-x
                                                                                                   :ws/message message))))
                                                                     (rf acc x))))))
                                                          xrf (xf (rf/result-fn))]
                                                      (fn
                                                        ([] (rf))
                                                        ([acc] (rf acc))
                                                        ([acc {:nio/keys [selection-key in out selector]
                                                               original-rf :context/rf
                                                               original-x :context/x
                                                               :repl/keys [client js
                                                                           input id]
                                                               :as x}]
                                                         (let [{client-x :context/x
                                                                :as client-attachment} (.attachment client)
                                                               client-x (assoc client-x
                                                                               :context/callback-rf rf
                                                                               :context/callback-x x
                                                                               :ws/message (j/write-str {:form js})
                                                                               :ws/op :text)]
                                                           (when-not @once
                                                             (->> (assoc client-attachment
                                                                         :context/rf xrf
                                                                         :context/x client-x)
                                                                  (.attach client))
                                                             (xrf acc client-x)
                                                             (prn ::ws ::started)
                                                             (vreset! once true))
                                                           (cond
                                                             ;; waiting to send response
                                                             (xrf)
                                                             (let [{:ws/keys [message]} (xrf)]
                                                               (rf acc (assoc x :ws/message message)))

                                                             :else
                                                             (do
                                                               (prn ::waiting)
                                                               acc)))))))
                                                  (comp
                                                   (map (fn [{:repl/keys [start]
                                                              :as x}]
                                                          (assoc x :repl/ms (quot (- (System/nanoTime) start) 1000000))))
                                                   (map (fn [{:ws/keys [message]
                                                              :repl/keys [cljs-ns ms]
                                                              :as x}]
                                                          (prn ::response message)
                                                          (let [{:keys [val]} (j/read-str message :key-fn keyword)]
                                                            (assoc x
                                                                   :http/status 200
                                                                   :http/reason "OK"
                                                                   :http/headers {:content-type "text/plain"
                                                                                  :connection "keep-alive"}
                                                                   :http/body (str cljs-ns " => " val " - " ms "ms" "\n")))))
                                                   #_(map (fn [x]
                                                            (def y x)
                                                            x))
                                                   #_(rf/debug-rf ::send)
                                                   (nio/send-rf (comp
                                                                 nio/response-rf))
                                                   nio/readable-rf))
                                                 (comp ;; no session
                                                  (map (fn [{:context/keys [repl-clients]
                                                             {input :form id :device-id :keys [repl-token]} :params
                                                             :keys [headers] :as x}]
                                                         (assoc x
                                                                :http/body (str "No active session for " id))))
                                                  nio/writable-rf
                                                  (nio/send-rf (comp
                                                                nio/response-rf)))))
                                     :default (comp
                                               (map (fn [{:keys [uuid] :as x}]
                                                      (assoc x
                                                             :http/status 403
                                                             :http/reason "FORBIDDEN"
                                                             :http/headers {:content-type "text/plain"
                                                                            :connection "keep-alive"}
                                                             :http/body "Forbidden")))
                                               (comp
                                                nio/writable-rf
                                                (nio/send-rf (comp
                                                              nio/response-rf))
                                                nio/readable-rf))}))
                          "/repl/ws" (comp
                                      (map (fn [{:context/keys [repl-clients]
                                                 :nio/keys [selection-key]
                                                 {:keys [sec-websocket-key]} :headers
                                                 {:keys [id]} :params
                                                 :as x}]
                                             (prn ::new ::repl id selection-key)
                                             (vswap! repl-clients assoc id selection-key)
                                             (assoc x
                                                    :http/status 101
                                                    :http/reason "Switching Protocols"
                                                    :http/headers {:upgrade "websocket"
                                                                   :connection "upgrade"
                                                                   :sec-websocket-accept (websocket/handshake sec-websocket-key)})))
                                      (comp
                                       nio/writable-rf
                                       (nio/send-rf (comp
                                                     nio/response-rf))
                                       nio/readable-rf
                                       #_(drop-while (fn [x] true))
                                       #_(nio/receive-rf
                                          (comp
                                           websocket/decode-frame-rf
                                           websocket/decode-message-rf
                                           (rf/repeatedly-rf
                                            (nio/send-rf
                                             (comp
                                              websocket/encode-message-rf
                                              websocket/encode-frame-rf)))
                                           (fn [rf]
                                             (let [once (volatile! false)]
                                               (fn
                                                 ([] (rf))
                                                 ([acc] (rf acc))
                                                 ([acc {:nio/keys [selection-key]
                                                        :context/keys [ws]
                                                        :ws/keys [message op frames]
                                                        :as x}]
                                                  (prn ::message op)
                                                  acc))))))))}))
               "/out" (comp
                       (map (fn [{:keys [path] :as x}]
                              (assoc x :file/path (str "." path))))
                       (rf/catch-rf
                        NoSuchFileException
                        (fn [x] (assoc x :file/size 0))
                        (comp
                         storage/file-rf
                         storage/open-rf
                         storage/read-rf
                         storage/flip-rf
                         storage/close-rf))
                       (rf/branch (fn [{:file/keys [size]}]
                                    (some-> size (> 0)))
                                  (map (fn [{:keys [path]
                                             :file/keys [^ByteBuffer buf content-type]
                                             :as x}]
                                         (prn ::content content-type buf)
                                         (assoc x
                                                :http/status 200
                                                :http/reason "OK"
                                                :http/headers {:content-type content-type
                                                               :connection "keep-alive"}
                                                :http/body buf)))
                                  (map (fn [{:keys [path]
                                             :as x}]
                                         (assoc x
                                                :http/status 404
                                                :http/reason "Not Found"
                                                :http/headers {:content-type "text/plain"
                                                               :connection "keep-alive"}
                                                :http/body (str "Not found: " path)))))
                       (comp
                        nio/writable-rf
                        (nio/send-rf (comp
                                      nio/response-rf))
                        nio/readable-rf))
               "/remote" (comp
                          (rf/choose-rf
                           (fn [{{:keys [ns var]} :params
                                 :as x}]
                             (let [sym (symbol ns var)]
                               (->
                                (ns-resolve (symbol (namespace sym)) (symbol (name sym)))
                                (boolean))))
                           {true (comp
                                  (fn [rf]
                                    (let [xrfm (volatile! {})]
                                      (fn
                                        ([] (rf))
                                        ([acc] (rf acc))
                                        ([acc {{:keys [ns var]} :params
                                               :remote/keys [xf]
                                               :as x}]
                                         (let [sym (symbol ns var)]
                                           (when-not (get @xrfm sym)
                                             (vswap! xrfm assoc sym
                                                     (-> (ns-resolve (symbol (namespace sym)) (symbol (name sym)))
                                                         (apply [(rf/result-fn)]))))
                                           (-> (get @xrfm sym)
                                               (apply [acc x]))
                                           (if-let [x' (-> (get @xrfm sym)
                                                           (apply []))]
                                             (rf acc x')
                                             acc)))))))
                            :default (comp
                                      (map (fn [{{:keys [ns var]} :params
                                                 :as x}]
                                             (assoc x
                                                    :http/status 200
                                                    :http/reason "OK"
                                                    :http/headers {:content-type "text/html"
                                                                   :connection "keep-alive"}
                                                    :http/body (str "Unable to resolve " ns "/" var))))
                                      (comp
                                       nio/writable-rf
                                       (nio/send-rf nio/response-rf)
                                       nio/readable-rf))}))
               "/" (comp
                    (map (fn [{:app/keys [uuid]
                               {:keys [x-appengine-city
                                       x-appengine-country
                                       x-appengine-region
                                       x-appengine-user-ip
                                       x-cloud-trace-context]} :headers
                               :as x}]
                           (assoc x
                                  :http/status 200
                                  :http/reason "OK"
                                  :http/headers {:content-type "text/html"
                                                 :connection "keep-alive"}
                                  :http/body (root x))))
                    (comp
                     nio/writable-rf
                     (nio/send-rf (comp
                                   nio/response-rf))
                     nio/readable-rf))
               :default (comp
                         (map (fn [{:keys [path]
                                    {:keys [host]} :headers
                                    :as x}]
                                (prn ::404 path)
                                (assoc x
                                       :http/status 404
                                       :http/reason "Not Found"
                                       :http/headers {:content-type "text/plain"
                                                      :connection "keep-alive"}
                                       :http/body (str "NOT FOUND " path " @ " host))))
                         (comp
                          nio/writable-rf
                          (nio/send-rf (comp
                                        nio/response-rf))
                          nio/readable-rf))})))
           nio/valid-rf
           (map (fn [x] (prn ::repeatedly) x))))))))
     nio/close-rf))))

;; TODO: clean up
(def send-response-rf (comp
                       nio/writable-rf
                       (nio/send-rf (comp
                                     nio/response-rf))
                       nio/readable-rf))

#_(

   (in-ns 'jaq.http.xrf.repl)
   (into []
         (comp
          (map (fn [{:keys [path] :as x}]
                 (assoc x :file/path (str "." path))))
          (rf/catch-rf
           NoSuchFileException
           (fn [x] (assoc x :file/size 0))
           (comp
            storage/file-rf
            storage/open-rf
            storage/read-rf
            storage/flip-rf
            storage/close-rf))
          (rf/branch (fn [{:file/keys [size]}]
                       (some-> size (> 0)))
                     (map (fn [{:keys [path]
                                :file/keys [^ByteBuffer buf content-type]
                                :as x}]
                            (assoc x
                                   :http/status 200
                                   :http/reason "OK"
                                   :http/headers {:content-type content-type
                                                  :connection "keep-alive"}
                                   :http/body buf)))
                     (map (fn [{:keys [path]
                                :as x}]
                            (assoc x
                                   :http/status 404
                                   :http/reason "Not Found"
                                   :http/headers {:content-type "text/plain"
                                                  :connection "keep-alive"}
                                   :http/body (str "Not found: " path))))))
         [{:path "/out/goog/base.js"}])

   (def index-rf (comp
                  (map (fn [{:app/keys [uuid]
                             {:keys [x-appengine-city
                                     x-appengine-country
                                     x-appengine-region
                                     x-appengine-user-ip
                                     x-cloud-trace-context]} :headers
                             :as x}]
                         (assoc x
                                :http/status 200
                                :http/reason "OK"
                                :http/headers {:content-type "text/html"
                                               :connection "keep-alive"}
                                :http/body (root x))))
                  (comp
                   nio/writable-rf
                   (nio/send-rf (comp
                                 nio/response-rf))
                   nio/readable-rf)))
   )


#_(
   *ns*
   *e
   (in-ns 'jaq.http.xrf.repl)
   (require 'jaq.http.xrf.repl :reload)

   (def x
     (->> [{:context/bip-size (* 10 4096)
            :context/repl-clients (volatile! {})
            :http/host "localhost"
            :http/scheme :http
            :http/port 8080 #_10010
            :http/minor 1 :http/major 1}]
          (into [] repl-rf)
          (first)))
   (-> x :context/shutdown! (apply []))
   (->> x :nio/selector (.keys) (map (fn [sk]
                                       (-> sk (.channel) (.close))
                                       (-> sk (.cancel)))) (doall))
   (-> x :nio/selector (.close))
   (in-ns 'jaq.http.xrf.repl)

   (->> x :nio/selector (.keys))
   ;; close UDP socket. TODO: by protocol
   (->> x :nio/selector
        (.keys)
        (filter (fn [sk]
                  (-> sk (.channel) (.socket) (.getLocalPort) (= 48073))))
        (map (fn [sk]
               (-> sk (.channel) (.close))
               (-> sk (.cancel))))
        (doall))
   (in-ns 'jaq.http.xrf.repl)



   (-> x :context/repl-clients (deref))

   (into []
         (comp
          nio/response-rf
          (map :http/req))
         [y])

   (keys y)
   (-> y :nio/selection-key (.attachment) :context/x :context/x keys)
   (-> y :ws/client)
   (-> y :nio/selection-key)
   (-> y :http/request keys)
   (-> y :params)
   (-> y :http/body)
   (-> y :http/headers)
   (-> y :nio/in)

   nio/read-op
   nio/write-op

   (-> x :context/repl-clients deref (get "1234") (.attachment) :context/x (nio/read!))
   )
