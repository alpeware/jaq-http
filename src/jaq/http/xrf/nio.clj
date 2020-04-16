(ns jaq.http.xrf.nio
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [clojure.java.io :as io]
   [jaq.async.fj :as fj]
   [jaq.gcp.auth :as auth]
   [jaq.gcp.appengine :as appengine]
   [jaq.gcp.storage :as storage]
   [jaq.http.xrf.bip :as bip]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.response :as response]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.rf :as rf]
   [net.cgrand.xforms :as x])
  (:import
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio.charset Charset]
   [java.nio ByteBuffer ByteOrder CharBuffer]
   [java.net InetSocketAddress ServerSocket Socket SocketAddress InetSocketAddress]
   [javax.net.ssl
    SNIHostName SNIServerName
    SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status
    SSLContext SSLSession]
   [java.util.concurrent ConcurrentLinkedDeque]
   [java.util Set]))

(def read-op SelectionKey/OP_READ)
(def write-op SelectionKey/OP_WRITE)

(defn address [^String host ^Integer port]
  (InetSocketAddress. host port))

(defn non-blocking [^AbstractSelectableChannel channel]
  (.configureBlocking channel false))

(defn ^SocketChannel channel! [^SocketAddress socket-address]
  (SocketChannel/open socket-address))

(defn ^ServerSocketChannel server-channel! []
  (ServerSocketChannel/open)
  #_(-> (ServerSocketChannel/open)
        (non-blocking)))

(defn ^ServerSocket socket [^ServerSocketChannel ssc]
  (.socket ssc)
  #_(doto (.socket ssc)
      (.setReuseAddress true)
      (.setReceiveBufferSize socket-buffer-size)))

#_(defn client-socket [^Socket socket]
    (doto socket
      (.setTcpNoDelay true)
      (.setReceiveBufferSize socket-buffer-size)
      (.setSendBufferSize socket-buffer-size)
      (.setReuseAddress true)))

;; TODO: backlog and address
(defn bind! [port ^ServerSocket socket]
  (.bind socket (InetSocketAddress. port)))

(defn ^Selector selector! [] (Selector/open))

(defn select! [^Selector selector]
  (.select selector))

(defn register! [^Selector selector attachment ^SocketChannel channel]
  (.register channel
             selector
             (bit-or SelectionKey/OP_CONNECT #_SelectionKey/OP_WRITE SelectionKey/OP_READ)
             attachment))

(defn ^SelectionKey listen! [^Selector selector attachment ^ServerSocketChannel server-channel]
  (.register server-channel selector SelectionKey/OP_ACCEPT attachment))

(defn ^SelectionKey readable [^Selector selector ^SocketChannel channel attachment]
  (.register channel selector SelectionKey/OP_READ attachment))

(defn ^SelectionKey writable [^Selector selector ^SocketChannel channel attachment]
  (.register channel selector SelectionKey/OP_WRITE attachment))

(defn ^SelectionKey readable! [^SelectionKey selection-key]
  (when (.isValid selection-key)
    (.interestOps selection-key SelectionKey/OP_READ)))

(defn ^SelectionKey writable! [^SelectionKey selection-key]
  (when (.isValid selection-key)
    (.interestOps selection-key SelectionKey/OP_WRITE)))

(defn ^SelectionKey read-writable! [^SelectionKey selection-key]
  (when (.isValid selection-key)
    (.interestOps selection-key (bit-or SelectionKey/OP_WRITE SelectionKey/OP_READ))))

(defn wakeup! [selection-keys]
  (->> selection-keys
       (map (fn [^SelectionKey sk]
              (.selector sk)))
       (set)
       (map (fn [^Selector e] (.wakeup e)))))

(defn accept! [^ServerSocketChannel server-channel]
  (.accept server-channel))

(defn connect! [^SelectionKey sk]
  (-> sk ^SocketChannel (.channel) (.finishConnect)))

(defn write-channel [^SocketChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn read-channel [^SocketChannel channel ^ByteBuffer buf]
  (.read channel buf))

(defn read! [{{:keys [reserve commit block decommit]} :nio/in
              :nio/keys [^SelectionKey selection-key]
              :as x}]
  (let [^SocketChannel channel (.channel selection-key)]
    (let [bb (reserve)
          n (->> bb
                 (read-channel channel))]
      (cond
        (< n 0) ;; end of stream
        (do
          (prn ::eos)
          (.interestOps selection-key 0)
          (.cancel selection-key))

        (> n 0) ;; read some bytes
        (do
          (prn ::read n)
          (->> bb
               (.flip)
               (commit))))
      n)))

(defn write! [{{:keys [reserve commit block decommit]} :nio/out
               :nio/keys [^SelectionKey selection-key]
               :as x}]
  (let [^SocketChannel channel (.channel selection-key)]
    (let [bb (block)]
      (when (.hasRemaining bb)
        (write-channel channel bb)
        #_(prn ::wrote (.position bb))
        (decommit bb))
      (.position bb))))

(def readable-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key]
             :as x}]
       (readable! selection-key)
       (rf acc x)))))

(def writable-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key]
             :as x}]
       (writable! selection-key)
       (rf acc x)))))

(def read-writable-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key]
             :as x}]
       (read-writable! selection-key)
       (rf acc x)))))

;; TODO: rename to buf-rf
;; TODO: remove?
(def attachment-rf
  (fn [rf]
    (let [attachment (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [^SelectionKey selection-key]
               :as x}]
         (when-not @attachment
           (->> {:nio/in (->> [{}] (into [] (comp
                                             bip/bip-rf
                                             (map :context/bip))) (first))
                 :nio/out (->> [{}] (into [] (comp
                                              bip/bip-rf
                                              (map :context/bip))) (first))
                 :context/rf rf
                 :context/acc acc
                 :context/x x}
                (vreset! attachment)))
         (->> (assoc x
                     ;;:nio/attachment @attachment
                     :nio/in (:nio/in @attachment)
                     :nio/out (:nio/out @attachment))
              (rf acc)))))))

(defn send-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          request (volatile! nil)
          requests (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :nio/keys [^SelectionKey selection-key]
               {:keys [reserve commit block decommit]} :nio/out
               :as x}]
         (if @once
           (rf acc x)
           (do
             (when-not @requests
               (xrf acc x)
               (when-let [{:http/keys [req] :as xr} (xrf)]
                 (->> req
                      (map (fn [e]
                             (cond
                               (string? e)
                               (-> (.getBytes e)
                                   (ByteBuffer/wrap))

                               (instance? ByteBuffer e)
                               e)))
                      (vreset! requests))))
             (when (and @request (not (.hasRemaining @request)))
               (vreset! request nil))
             (when (and (seq @requests) (not @request))
               (->> @requests
                    (first)
                    (vreset! request))
               (vswap! requests rest))
             (if (and @request (.hasRemaining @request))
               (let [dst (reserve)
                     limit (min (.remaining @request) (.remaining dst))
                     src (-> @request (.duplicate) #_(.limit limit))
                     pos (-> @request (.position))]
                 (->> src (.position) (+ limit) (.limit src))
                 (->> limit (+ pos) (.position @request))
                 (.put dst src)
                 (.flip dst)
                 (commit dst)
                 (let [written (write! x)]
                   (prn ::written written)
                   (if-not (> written 0)
                     (do
                       ;; socket buffer full so waiting to clear
                       (writable! selection-key)
                       acc)
                     (do
                       (recur acc x)))))
               (do
                 (->> x
                      (rf acc)))))))))))

#_(
   (in-ns 'jaq.http.xrf.nio)
   *ns*
   *e

   )

(defn receive-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          result (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :nio/keys [selection-key]
               {:keys [reserve commit block decommit]} :nio/in
               :as x}]
         (if-not @once
           (let [bb (block)]
             (if-not (.hasRemaining bb)
               (do ;; need more data
                 (readable! selection-key)
                 acc)
               (do
                 (->> bb
                      (.limit)
                      (range)
                      (map (fn [_]
                             (let [b (-> bb (.get))]
                               (->> (assoc x
                                           :byte b)
                                    (xrf acc)))))
                      (doall))
                 (decommit bb)
                 (if-let [xr (xrf)]
                   (do
                     (vreset! once true)
                     (vreset! result xr)
                     (rf acc xr))
                   (recur acc x)))))
           (rf acc x)))))))

#_(
   *e
   )
(def request-rf
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [selection-key]
               :http/keys [req]
               :context/keys [^ByteBuffer src]
               {:keys [reserve commit block decommit]} :nio/out
               :as x}]
         (when-not @once
           (let [dst (reserve)
                 src  (->> req
                           (clojure.string/join)
                           (.getBytes)
                           (ByteBuffer/wrap))
                 ]
             (.put dst src)
             (.flip dst)
             (commit dst)
             (write! x)
             (vreset! once true)))
         (let [bb (block)]
           (if (.hasRemaining bb)
             (rf acc)
             (rf acc x))))))))

(def response-rf
  (fn [rf]
    (let [once (volatile! false)
          parsed (volatile! false)
          parsed! (fn []
                    (vswap! parsed not))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               {:keys [reserve commit block decommit]} :nio/in
               :as x}]
         (let [bb (block)]
           (when (.hasRemaining bb)
             (->> bb
                  (.limit)
                  (range)
                  (map (fn [_]
                         (let [b (-> bb (.get))]
                           (if @parsed
                             (->> (assoc x
                                         :context/parsed! parsed!
                                         :byte b)
                                  (rf acc))
                             (->> (assoc x
                                         :context/parsed! parsed!
                                         :char (char b))
                                  (rf acc))))))
                  (doall))
             (decommit bb))
           (rf acc)))))))

(def read-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (and (.isValid selection-key)
                  (.isReadable selection-key))
         (read! x))
       (rf acc x)))))

(def write-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (and (.isValid selection-key)
                  (.isWritable selection-key))
         (write! x))
       (rf acc x)))))

(def connect-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (.isConnectable selection-key)
         (connect! selection-key))
       (rf acc x)))))

(def valid-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when-not (.isValid selection-key)
         (.cancel selection-key))
       (rf acc x)))))

(defn channel-rf [xf]
  (fn [rf]
    (let [channel (volatile! nil)
          selection-key (volatile! nil)
          continuation-rf (fn [parent-rf]
                            (fn [rf]
                              (fn
                                ([] (rf))
                                ([acc] (rf acc))
                                ([acc x]
                                 (parent-rf acc x)))))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :nio/keys [selector attachment]
               :as x}]
         (when-not @channel
           (->> (address host port)
                (channel!)
                (non-blocking)
                (vreset! channel)
                (register! selector
                           (assoc x ;;attachment
                                  :context/x (assoc x
                                                    :nio/in (->> [x] (into [] (comp
                                                                               bip/bip-rf
                                                                               (map :context/bip))) (first))
                                                    :nio/out (->> [x] (into [] (comp
                                                                                bip/bip-rf
                                                                                (map :context/bip))) (first)))
                                  ;;:context/rf (xf (rf/result-fn))
                                  :context/rf ((comp
                                                xf
                                                (continuation-rf rf))
                                               (rf/result-fn))))
                (writable!)
                (vreset! selection-key))
           (-> @selection-key
               ;; TODO: fix
               (.attachment)
               (assoc-in [:context/x :nio/selection-key] @selection-key)
               (->> (.attach @selection-key))))
         (->> (assoc x
                     :nio/channel @channel
                     :nio/selection-key ^SelectionKey @selection-key)
              (rf acc)))))))

(defn accept-rf [xf]
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [attachment
                        ^Selector selector
                        ^SelectionKey selection-key]
             :as x}]
       (when (.isAcceptable selection-key)
         (let [sk (some->> selection-key
                           (.channel)
                           (accept!)
                           (non-blocking)
                           (register! selector
                                      (assoc x
                                             :context/x (assoc x
                                                               :nio/in (->> [x] (into [] (comp
                                                                                          bip/bip-rf
                                                                                          (map :context/bip))) (first))
                                                               :nio/out (->> [x] (into [] (comp
                                                                                           bip/bip-rf
                                                                                           (map :context/bip))) (first)))
                                             :context/rf (xf (rf/result-fn))))
                           (readable!))]
           (-> sk
               ;; TODO: fix
               (.attachment)
               (assoc-in [:context/x :nio/selection-key] sk)
               (->> (.attach sk)))))
       (rf acc x)))))

(defn bind-rf [xf]
  (fn [rf]
    (let [server-channel (volatile! nil)
          selection-key (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :nio/keys [selector attachment]
               :as x}]
         (when-not @server-channel
           (->> (server-channel!)
                (non-blocking)
                (vreset! server-channel)
                (listen! selector (assoc x
                                         :context/x (assoc x
                                                           :nio/in (->> [x] (into [] (comp
                                                                                      bip/bip-rf
                                                                                      (map :context/bip))) (first))
                                                           :nio/out (->> [x] (into [] (comp
                                                                                       bip/bip-rf
                                                                                       (map :context/bip))) (first)))
                                         :nio/server-channel @server-channel
                                         :context/rf (xf (rf/result-fn))))
                (vreset! selection-key)
                ^SelectionKey (.channel)
                (socket)
                (bind! port))
           ;; TODO: fix
           (-> @selection-key
               (.attachment)
               (assoc-in [:context/x :nio/selection-key] @selection-key)
               (->> (.attach @selection-key)))
           (prn ::listening port))
         (->> (assoc x
                     :nio/server-channel ^ServerSocketChannel @server-channel
                     :nio/selection-key ^SelectionKey @selection-key)
              (rf acc)))))))

(def selector-rf
  (fn [rf]
    (let [sl (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :nio/keys [selector]
               :as x}]
         (when-not @sl
           (let [selector (or selector (selector!))]
             (->> selector
                  (vreset! sl))))
         (->> (assoc x :nio/selector ^Selector @sl)
              (rf acc)))))))

(defn select-rf [xf]
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [^Selector selector]
               :as x}]
         (when-not @once
           (-> (xf (rf/result-fn))
               (apply [acc x]))
           (vreset! once true))
         (if (-> selector (.keys) (empty?))
           (rf acc x)
           (do
             (when (> (select! selector) 0)
               (let [^Set keys-set (.selectedKeys selector)
                     selected-keys (into #{} keys-set)]
                 (.clear keys-set)
                 (doseq [^SelectionKey sk selected-keys]
                   (let [{:context/keys [rf acc x]
                          :as attachment} (.attachment sk)]
                     ;; TODO: should we do something w/ return values from channels like cleaning up?
                     (when-not (:nio/out x)
                       #_(prn ::sk sk ::attachment attachment))
                     (rf acc (assoc x
                                    :nio/selection-key sk
                                    ;;:nio/attachment attachment
                                    ))))))
             acc)))))))

(def close-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [selector]
             :as x}]
       (prn ::closing)
       (let [results (volatile! {})]
         (doseq [sk (.keys selector)]
           (let [{:context/keys [rf acc x]
                  :as attachment} (.attachment sk)]
             (vswap! results assoc sk (rf))
             (some-> sk (.channel) (.close))
             (.cancel sk)))
         (.close selector)
         (rf acc (assoc x :context/results @results)))))))

(defn thread-rf [xf]
  (fn [rf]
    (let [thread (volatile! nil)
          result (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [selector]
               :as x}]
         (when-not @thread
           (->> (fj/thread
                  (loop [xf (xf (rf/result-fn))]
                    (if-let [r (xf)]
                      (vreset! result r)
                      (do
                        (xf acc x)
                        (recur xf))))
                  #_(-> (xf (rf/result-fn))
                        (steps acc (assoc x :async/stop stop))))
                (vreset! thread)))
         (rf acc (assoc x
                        :async/result result
                        :async/thread @thread)))))))

#_(
   (into []
         (thread-rf
          (comp
           (let [vv (volatile! nil)]
             (map (fn [{:keys [v] :as x}]
                    (when-not @vv
                      (vreset! vv v))
                    (assoc x :v (vswap! vv inc)))))
           (remove (fn [{:keys [v]}]
                     (< v 10)))))
         [{:v 0}])
   (def t *1)
   (-> t first :async/result deref)
   (-> t first :async/stop! (apply []))
   (-> t first :async/thread .getState)

   )

;; TODO: move to http
(def body-rf
  (comp
   (map (fn [{:http/keys [chunks] :as e}]
          (assoc e :http/body (first chunks))))
   (map (fn [{:http/keys [body]
              {:keys [content-type]} :headers
              :keys [status]
              :as e}]
          (if (string/includes? content-type "application/json")
            (assoc e :http/json (clojure.data.json/read-str body :key-fn keyword))
            e)))
   (map (fn [{:http/keys [json] :as e}]
          (let [normalize (fn [k] (-> k (name) (string/replace #"_" "-") (keyword)))
                f (fn [[k v]] (if (keyword? k) [(normalize k) v] [k v]))]
            (if json
              (->> json
                   (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)))
                   (assoc e :http/json))
              e))))))

;; TODO: move to http
(def response-rf
  (comp
   (map (fn [x] (assoc x :http/req [])))
   (map (fn [{:http/keys [req headers host] :as x}]
          (assoc x :http/headers (conj {:Host host} headers))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "HTTP")))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "/")))
   (map (fn [{:http/keys [req major minor] :as x}]
          (update x :http/req conj (str major "." minor))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj " ")))
   (map (fn [{:http/keys [req major status reason] :as x}]
          (update x :http/req conj (str status " " reason))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "\r\n")))
   (map (fn [{:http/keys [headers body] :as x}]
          (cond
            (not body)
            (update x :http/headers conj {:content-length 0})

            (string? body)
            (update x :http/headers conj {:content-length (count body)})

            (instance? java.nio.ByteBuffer body)
            (update x :http/headers conj {:content-length (.limit body)}))))
   http/headers-rf
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "\r\n")))
   (map (fn [{:http/keys [req body] :as x}]
          (if body
            (update x :http/req conj body)
            x)))))

(def ssl-connection
  (comp ;; ssl connection
   ssl/ssl-rf
   valid-rf
   connect-rf
   read-rf
   write-rf
   ;; need to register for both writable/readable
   (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                 (read-writable! selection-key)
                 x))
   #_(rf/debug-rf ::handshake)
   ssl/handshake-rf))

(def json-response
  (comp
   (rf/one-rf
    :http/response
    (comp
     (map (fn [{:keys [byte] :as x}]
            (assoc x :char (char byte))))
     header/response-line
     header/headers))
   (map (fn [{{:keys [headers status]} :http/response
              :as x}]
          (assoc x
                 :headers headers
                 :status status)))
   #_(rf/debug-rf ::response)
   http/chunked-rf
   http/text-rf
   body-rf))

(def close-connection
  (comp
   (map (fn [{:http/keys [chunks body json]
              :nio/keys [^SelectionKey selection-key ^Selector selector]
              :keys [headers]
              :as x}]
          ;; clean up channel
          (prn ::cleanup selection-key)
          (-> selection-key (.channel) (.close))
          (.cancel selection-key)
          (.wakeup selector)
          x))))

(def auth-chan
  (comp
   auth/credentials-rf
   auth/refresh-rf ;; provides hostname
   (rf/branch (fn [{:oauth2/keys [expires-in]}]
                (> (System/currentTimeMillis) expires-in))
              (channel-rf
               (comp
                ssl-connection
                (rf/debug-rf ::attachment)
                ;; send ssl rf
                (ssl/request-ssl-rf
                 http/http-rf)
                ;; wait for response
                (ssl/receive-ssl-rf
                 json-response)
                ;; process response
                (map (fn [{{:keys [expires-in]} :http/json
                           :as x}]
                       (if expires-in
                         (->> expires-in
                              (* 1000)
                              (+ (System/currentTimeMillis))
                              (assoc-in x [:http/json :expires-in]))
                         x)))
                (map (fn [{:http/keys [json]
                           :context/keys [request]
                           :as x}]
                       (let [oauth2 (->> json
                                         (map (fn [[k v]]
                                                [(keyword "oauth2" (name k)) v]))
                                         (into {}))]
                         (prn ::oauth2 oauth2)
                         (merge x oauth2))))
                auth/store-rf
                #_(rf/debug-rf ::done)
                ;; clean up connection
                close-connection))
              rf/identity-rf)
   (drop-while (fn [{:oauth2/keys [expires-in]}]
                 (> (System/currentTimeMillis) expires-in)))
   #_(rf/debug-rf ::authed)))

#_(
   *e
   *ns*
   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.nio :reload)

   (->> (System/getenv)
        (into {})
        (clojure.walk/keywordize-keys))

   (slurp "http://localhost:8081/")

   ;; MTU size per interface
   (->> (java.net.NetworkInterface/getNetworkInterfaces)
        (enumeration-seq)
        (map (fn [e] [(.getDisplayName e) (.getMTU e)])))

   ;; repl server
   (let [xf (comp
             (map (fn [x]
                    (let [shutdown (volatile! nil)]
                      (assoc x
                             :context/shutdown shutdown
                             :context/shutdown! (fn []
                                                  (-> @shutdown (apply [])))))))
             (thread-rf
              (comp
               selector-rf
               #_attachment-rf
               (select-rf
                (comp
                 (bind-rf
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
                   (accept-rf
                    (comp
                     #_attachment-rf
                     valid-rf
                     read-rf
                     write-rf
                     (rf/repeatedly-rf
                      (comp
                       (receive-rf
                        (comp
                         #_(rf/debug-rf ::receive)
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
                                                              :http/reason "FORBIDDEN"
                                                              :http/headers {:content-type "text/plain"
                                                                             :connection "keep-alive"}
                                                              :http/body "Forbidden"))))))
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
                                             :http/headers {:content-type "text/plain"
                                                            :connection "keep-alive"}
                                             :http/body (str "You are from " x-appengine-city " in "
                                                             x-appengine-region " / " x-appengine-country "."
                                                             " Your IP is " x-appengine-user-ip " and your trace is "
                                                             x-cloud-trace-context "."))))
                           :default (map (fn [{:app/keys [uuid]
                                               {:keys [host]} :headers
                                               :as x}]
                                           (assoc x
                                                  :http/status 404
                                                  :http/reason "NOT FOUND"
                                                  :http/headers {:content-type "text/plain"
                                                                 :connection "keep-alive"}
                                                  :http/body "NOT FOUND")))})))
                       writable-rf
                       #_(rf/once-rf (fn [{:nio/keys [^SelectionKey selection-key] :as x}]
                                       (writable! selection-key)
                                       x))
                       (send-rf (comp
                                 response-rf))
                       #_(rf/debug-rf ::send)
                       (rf/once-rf (fn [{:nio/keys [^SelectionKey selection-key] :as x}]
                                     (readable! selection-key)
                                     x))))))))))
               close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/host "localhost"
            :http/scheme :http
            :http/port 10010
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))
   (-> x :context/shutdown! (apply []))
   (-> x :async/thread (.stop))
   (def s *1)
   (-> s (.keys))
   (->> s (.keys) (map (fn [sk]
                         (-> sk (.channel) (.close))
                         (-> sk (.cancel)))) (doall))
   (-> s .close)
   *e
   *ns*

   (in-ns 'jaq.http.xrf.nio)

   (def x (first *1))

   (->> x :nio/selector (.keys) #_(map (fn [e]
                                         (-> e (.channel) (.close))
                                         (.cancel e))))

   (-> x :nio/selector (.keys)
       (last) #_((fn [sk]
                   (let [{{{:keys [reserve commit block decommit]} :context/bip} :nio/out
                          :as attachment} (.attachment sk)
                         ^SocketChannel channel (.channel sk)]
                     (block)))))

   (-> x :async/stop! (apply []))
   (-> x :async/result (deref))
   *e
   (require 'clojure.reflect)
   (-> x :nio/selector (.isOpen))

   ;; http
   (let [xf (comp
             (thread-rf
              (comp
               selector-rf
               attachment-rf
               (select-rf
                (channel-rf
                 (comp
                  valid-rf
                  connect-rf
                  read-rf
                  write-rf
                  #_(rf/debug-rf ::send)
                  (send-rf http/http-rf)
                  ;; wait for response
                  readable-rf
                  #_(rf/debug-rf ::receive)
                  (receive-rf
                   (comp
                    (rf/one-rf
                     :http/response
                     (comp
                      (map (fn [{:keys [byte] :as x}]
                             (assoc x :char (char byte))))
                      header/response-line
                      header/headers))
                    (map (fn [{{:keys [headers status]} :http/response
                               :as x}]
                           (assoc x
                                  :headers headers
                                  :status status)))
                    #_(rf/debug-rf ::response)
                    http/chunked-rf
                    http/text-rf
                    body-rf))
                  #_(rf/debug-rf ::text)
                  (rf/once-rf (fn [{:http/keys [body]
                                    :nio/keys [selector selection-key]
                                    :as x}]
                                (-> selection-key (.channel) (.close))
                                (.cancel selection-key)
                                (.wakeup selector)
                                (prn ::body body)
                                x)))))
               close-rf)))]
     (->> [{:http/host "jaq.alpeware.com"
            :http/scheme :http
            :http/port 80
            :http/path "/"
            :http/minor 1 :http/major 1
            :http/method :GET}]
          (into [] xf)))
   (def x (first *1))
   (-> x :async/thread (.getState))
   (-> x :async/thread (.stop))
   (-> x :async/result (deref) :context/results)
   (keys x)
   read-op
   write-op
   (-> x :nio/selector (.keys) #_(first))
   (-> x :nio/selector (.keys) (first) (.attachment) (keys))
   (-> x :nio/selector (.keys) (first) (read!))
   (-> x :nio/selector (.keys) (first) (.isWritable))
   (-> x :nio/selector (.keys) (first) (.attachment) :nio/in :context/bip :block (apply []))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x :nio/selection-key)
   (->> x :async/result)
   (-> x :async/stop! (apply []))
   (-> x :async/thread (.getState))
   (-> x :async/thread (.stop))

   *ns*
   (in-ns 'jaq.http.xrf.nio)

   ;; https
   (let [xf (comp
             (thread-rf
              (comp
               selector-rf
               attachment-rf
               (select-rf
                (channel-rf
                 (comp
                  ssl/ssl-rf
                  valid-rf
                  connect-rf
                  read-rf
                  write-rf
                  ;; need to register for both writable/readable
                  ;;read-writable-rf
                  (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                                (read-writable! selection-key)
                                x))
                  #_(rf/debug-rf ::handshaking)
                  ssl/handshake-rf
                  (ssl/request-ssl-rf
                   http/http-rf)
                  #_(rf/debug-rf ::send)
                  ;; wait for response
                  #_(rf/debug-rf ::receive)
                  (ssl/receive-ssl-rf
                   (comp
                    (rf/one-rf
                     :http/response
                     (comp
                      (map (fn [{:keys [byte] :as x}]
                             (assoc x :char (char byte))))
                      header/response-line
                      header/headers))
                    (map (fn [{{:keys [headers status]} :http/response
                               :as x}]
                           (assoc x
                                  :headers headers
                                  :status status)))
                    #_(rf/debug-rf ::response)
                    http/chunked-rf
                    http/text-rf
                    (drop-while (fn [{{:keys [content-length transfer-encoding]} :headers}]
                                  (and
                                   (= transfer-encoding "chunked")
                                   (> content-length 0))))
                    #_body-rf))
                  #_(rf/debug-rf ::text)
                  (rf/once-rf (fn [{:http/keys [chunks body json]
                                    :nio/keys [^SelectionKey selection-key ^Selector selector]
                                    :keys [headers]
                                    :as x}]
                                ;; clean up channel
                                (-> selection-key (.channel) (.close))
                                (.cancel selection-key)
                                (.wakeup selector)
                                (prn ::headers headers)
                                (prn ::body body)
                                (prn ::json json)
                                (prn ::chunks chunks)
                                x)))))
               close-rf)))]
     (->> [{:context/bip-size (* 5 4096)
            :http/host "jaq.alpeware.com"
            ;;:http/host "www.google.com"
            ;;:http/host "news.ycombinator.com"
            ;;:http/host "www.wikipedia.org" ;; certificate errors
            ;;:http/host "www.amazon.com"
            :http/scheme :https
            :http/port 443
            :http/path "/"
            :http/minor 1 :http/major 1
            :http/method :GET}]
          (into [] xf)))

   ;; auth
   (let [ssl-connection (comp ;; ssl connection
                         ssl/ssl-rf
                         valid-rf
                         connect-rf
                         read-rf
                         write-rf
                         ;; need to register for both writable/readable
                         (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                                       (read-writable! selection-key)
                                       x))
                         (rf/debug-rf ::handshake)
                         ssl/handshake-rf)
         json-response (comp
                        (rf/one-rf
                         :http/response
                         (comp
                          (map (fn [{:keys [byte] :as x}]
                                 (assoc x :char (char byte))))
                          header/response-line
                          header/headers))
                        (map (fn [{{:keys [headers status]} :http/response
                                   :as x}]
                               (assoc x
                                      :headers headers
                                      :status status)))
                        #_(rf/debug-rf ::response)
                        http/chunked-rf
                        http/text-rf
                        body-rf)
         close-connection (comp
                           (map (fn [{:http/keys [chunks body json]
                                      :nio/keys [^SelectionKey selection-key ^Selector selector]
                                      :keys [headers]
                                      :as x}]
                                  ;; clean up channel
                                  (prn ::cleanup selection-key)
                                  (-> selection-key (.channel) (.close))
                                  (.cancel selection-key)
                                  (.wakeup selector)
                                  x)))
         auth-chan (comp
                    auth/credentials-rf
                    auth/refresh-rf ;; provides hostname
                    (rf/branch (fn [{:oauth2/keys [expires-in]}]
                                 (> (System/currentTimeMillis) expires-in))
                               (channel-rf
                                (comp
                                 ssl-connection
                                 (rf/debug-rf ::attachment)
                                 ;; send ssl rf
                                 (ssl/request-ssl-rf
                                  http/http-rf)
                                 ;; wait for response
                                 (ssl/receive-ssl-rf
                                  json-response)
                                 ;; process response
                                 (map (fn [{{:keys [expires-in]} :http/json
                                            :as x}]
                                        (if expires-in
                                          (->> expires-in
                                               (* 1000)
                                               (+ (System/currentTimeMillis))
                                               (assoc-in x [:http/json :expires-in]))
                                          x)))
                                 (map (fn [{:http/keys [json]
                                            :context/keys [request]
                                            :as x}]
                                        (let [oauth2 (->> json
                                                          (map (fn [[k v]]
                                                                 [(keyword "oauth2" (name k)) v]))
                                                          (into {}))]
                                          (prn ::oauth2 oauth2)
                                          (merge x oauth2))))
                                 #_auth/store-rf
                                 #_(rf/debug-rf ::done)
                                 ;; clean up connection
                                 close-connection))
                               rf/identity-rf)
                    (drop-while (fn [{:oauth2/keys [expires-in]}]
                                  (> (System/currentTimeMillis) expires-in)))
                    #_(rf/debug-rf ::authed))
         xf (comp
             selector-rf
             (x/time
              (thread-rf
               (comp
                #_selector-rf
                (select-rf
                 (comp
                  auth-chan
                  (drop-while (fn [{:oauth2/keys [expires-in]}]
                                (and (not expires-in)
                                     (> (System/currentTimeMillis) expires-in))))
                  (rf/one-rf :oauth2/access-token (comp
                                                   (map :oauth2/access-token)))
                  #_(rf/debug-rf ::authed)
                  #_(map (fn [{:http/keys [json]
                               :as x}]
                           (let [oauth2 (->> json
                                             (map (fn [[k v]]
                                                    [(keyword "oauth2" (name k)) v]))
                                             (into {}))]
                             (prn ::oauth2 oauth2)
                             (merge x oauth2))))
                  #_(rf/debug-rf ::authed)
                  (map (fn [x]
                         (-> x
                             (dissoc :http/json :http/body :http/chunks :http/headers)
                             (assoc :http/params {:project "alpeware-foo-bar"}))))
                  storage/list-buckets-rf
                  storage/rest-service-rf
                  #_(rf/debug-rf ::request)
                  (channel-rf
                   (comp
                    #_(rf/debug-rf ::request)
                    #_attachment-rf
                    ssl-connection
                    (ssl/request-ssl-rf http/http-rf)
                    #_(rf/debug-rf ::requested)
                    (ssl/receive-ssl-rf json-response)
                    (map (fn [{:http/keys [json chunks]
                               :as x}]
                           (assoc x :storage/items (:items json))))
                    close-connection))
                  (drop-while (fn [{:storage/keys [items] :as x}]
                                (nil? items)))
                  (map (fn [{:storage/keys [items]
                             :as x}]
                         (prn ::buckets items)
                         x))))
                close-rf))))]
     (->> [{:context/bip-size (* 5 4096)
            ;;:http/host "jaq.alpeware.com"
            :http/scheme :https
            :http/port 443
            :http/path "/"
            :http/minor 1 :http/major 1
            :http/method :GET}]
          (into [] xf)))
   (def x (first *1))
   (in-ns 'jaq.http.xrf.nio)
   (-> x :async/thread (.getState))
   (-> x :async/thread (.stop))
   (-> x :async/result (deref))

   (->> y (filter (fn [[k v]] (= "nio" (namespace k)))) (into {}))
   (-> x :nio/selector (.wakeup))
   (-> x :nio/selector (.keys) (empty?))
   (-> x :nio/selector (.keys))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x #_(write!))
   (def y *1)
   (-> y (write!))
   (-> y :nio/selection-key)
   (-> x :nio/selector (.keys) (first) (.isWritable))
   *e

   (->> x :http/chunks (count))
   (->> x :http/chunks (map count))
   (->> x :http/chunks (last))
   (->> x :headers)

   (into []
         (comp
          (map (fn [x]
                 (assoc x :http/params {:project "alpeware-foo-bar"})))
          storage/list-buckets-rf
          storage/rest-service-rf)
         [{}])

   ;; appengine deploy
   (let [selector (selector!)
         xf (comp
             (rf/branch (fn [{:oauth2/keys [expires-in]}]
                          (> (System/currentTimeMillis) expires-in))
                        auth-rf
                        rf/identity-rf)
             (comp
              ;; connection
              attachment-rf
              channel-rf
              ssl/ssl-rf
              process-rf
              ssl/handshake-rf
              ;; rest
              storage/list-objects-rf
              storage/rest-service-rf
              ;; request
              #_connection-rf
              http/http-rf
              selector-rf
              ssl/request-ssl-rf
              (fn [rf]
                (let [objects (volatile! [])
                      add-items! (fn [items]
                                   (vswap! objects into items))]
                  (fn
                    ([] (rf))
                    ([acc] (rf acc))
                    ([acc {:storage/keys [bucket]
                           {:keys [nextPageToken items]} :http/json
                           {:keys [location]} :headers
                           :context/keys [parsed! done!]
                           :as x}]
                     (-> x
                         (assoc :context/add-items! add-items!)
                         (assoc :context/objects objects)
                         (->> (rf acc)))))))
              ;; parse json
              (rf/once-rf
               (comp
                ssl/response-ssl-rf
                header/response-line
                header/headers
                http/parsed-rf
                http/chunked-rf
                http/text-rf
                body-rf
                (fn [rf]
                  (let [once (volatile! false)]
                    (fn
                      ([] (rf))
                      ([acc] (rf acc))
                      ([acc {:storage/keys [bucket]
                             {:keys [nextPageToken items]} :http/json
                             {:keys [location]} :headers
                             :context/keys [parsed! done! add-items!]
                             :as x}]
                       (when-not @once
                         (parsed!)
                         (add-items! items)
                         (vreset! once true))
                       (-> x
                           (dissoc :http/body)
                           (dissoc :http/chunks)
                           (assoc-in [:http/params :bucket] bucket)
                           (assoc-in [:http/params :pageToken] nextPageToken)
                           (->> (rf acc)))))))
                (rf/branch (fn [{{:keys [nextPageToken]} :http/json}]
                             nextPageToken)
                           (comp
                            http/http-rf
                            ssl/request-ssl-rf)
                           (fn [rf]
                             (let [once (volatile! false)]
                               (fn
                                 ([] (rf))
                                 ([acc] (rf acc))
                                 ([acc {:storage/keys [objects bucket]
                                        {:keys [nextPageToken items]} :http/json
                                        {:keys [location]} :headers
                                        :context/keys [parsed! done!]
                                        :as x}]
                                  (when-not @once
                                    (done!)
                                    (vreset! once true))
                                  (rf acc x))))))))
              (drop-while (fn [{{:keys [nextPageToken]} :http/json :as x}]
                            nextPageToken))
              (map (fn [{:nio/keys [selection-key] :as x}]
                     (when (.isValid selection-key)
                       (prn ::cancel ::selection-key)
                       (.cancel selection-key))
                     x))
              (fn [rf]
                (fn
                  ([] (rf))
                  ([acc] (rf acc))
                  ([acc {:context/keys [objects]
                         :appengine/keys [app service]
                         :storage/keys [bucket]
                         :as x}]
                   (-> x
                       (dissoc :http/params)
                       (dissoc :http/headers)
                       (dissoc :http/body)
                       (dissoc :http/req)
                       (dissoc :http/chunks)
                       (dissoc :http/json)
                       (assoc-in [:http/params :app] app)
                       (assoc-in [:http/params :service] service)
                       (assoc :storage/objects @objects)
                       (assoc :http/host appengine/root-url)
                       (->> (rf acc))))))
              (comp
               attachment-rf
               channel-rf
               ssl/ssl-rf
               process-rf
               ssl/handshake-rf)
              ;; rest
              appengine/version-rf
              appengine/create-version-rf
              appengine/rest-service-rf
              ;; request
              (comp
               http/http-rf
               ssl/request-ssl-rf
               ssl/response-ssl-rf
               header/response-line
               header/headers
               http/parsed-rf
               http/chunked-rf
               http/text-rf
               body-rf)
              (drop-while (fn [{{:keys [content-length]} :headers}]
                            (> content-length 0)))
              ;; operation
              (rf/branch
               (fn [{:keys [status] :as x}]
                 (= status 200))
               (comp
                (fn [rf]
                  (let [once (volatile! false)]
                    (fn
                      ([] (rf))
                      ([acc] (rf acc))
                      ([acc {{:keys [name]} :http/json
                             :http/keys [req]
                             :context/keys [parsed! done!]
                             :as x}]
                       (when-not @once
                         #_(prn ::req req)
                         (prn ::name name)
                         (done!)
                         (vreset! once true))
                       (-> x
                           (dissoc :http/body)
                           (dissoc :http/chunks)
                           (dissoc :rest/method)
                           (dissoc :context/objects)
                           (dissoc :storage/objects)
                           (assoc :http/params {:name name})
                           (->> (rf acc)))))))
                appengine/operation-rf
                appengine/rest-service-rf
                http/http-rf
                ssl/request-ssl-rf
                ssl/response-ssl-rf
                header/response-line
                header/headers
                http/parsed-rf
                http/chunked-rf
                http/text-rf
                body-rf)
               rf/identity-rf)
              (map (fn [x]
                     (-> x
                         (dissoc :context/x)
                         (dissoc :nio/attachment))))))
         rf (xf (rf/result-fn))]
     (rf nil
         (merge
          {:nio/selector selector
           :context/bip-size (* 5 4096)
           :storage/bucket "staging.alpeware-foo-bar.appspot.com"
           ;;:storage/prefix "target/classes/jaq/async"
           :storage/prefix "app/v3"
           :appengine/id (str (System/currentTimeMillis))
           :appengine/app "alpeware-foo-bar"
           :appengine/service :default
           :http/params {;;:prefix "target/classes/jaq/async"
                         :prefix "app/v3"
                         :bucket "staging.alpeware-foo-bar.appspot.com"}
           :http/host storage/root
           :http/scheme :https
           :http/port 443
           :http/minor 1 :http/major 1}
          oauth2))
     (let [step (partial reactor-main selector)
           start (System/currentTimeMillis)
           timeout (* 2 60 1000)
           steps (fn []
                   (if-let [r (rf)]
                     (def x r)
                     (when (< (System/currentTimeMillis) (+ start timeout))
                       (step)
                       (recur))))]
       (steps)
       #_step
       #_{:rf rf :step step :steps steps}))

   (slurp "https://alpeware-foo-bar.appspot.com/")
   *ns*
   *e
   (def x *1)
   (keys x)
   (clojure.pprint/pprint x)
   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.nio)

   (-> x :rest/method)
   (-> x :http/req)

   (->> x :storage/objects)
   (->> x :rest/path)
   (->> x :http/params)
   (->> x :http/headers)
   (->> x :http/path)
   (->> x :http/method)
   (->> x :http/host)
   (->> x :http/body)
   (->> x :http/json)
   (->> x :headers)
   (->> x :status)

   (into []
         (comp
          appengine/version-rf
          appengine/create-version-rf
          appengine/rest-service-rf
          http/http-rf
          (map :http/body))
         [x
          #_(select-keys x [:http/method :http/host :http/path :http/body])])

   (into []
         (comp
          (map (fn [x] (prn (x :http/body)) x))
          http/http-rf
          (map :http/req))
         [x
          #_(select-keys x [:http/method :http/host :http/path :http/body])])

   (into [] http/http-rf [#:http{:method :GET :host :foo :path :bar}])

   ;; upload
   (let [xf (comp
             selector-rf
             (thread-rf
              (comp
               (select-rf
                (comp
                 auth-chan
                 (drop-while (fn [{:oauth2/keys [expires-in]}]
                               (and (not expires-in)
                                    (> (System/currentTimeMillis) expires-in))))
                 (rf/one-rf :oauth2/access-token (comp
                                                  (map :oauth2/access-token)))
                 (map (fn [x]
                        (-> x
                            (dissoc :http/json :http/body :http/chunks :http/headers :ssl/engine)
                            (assoc :http/params {:bucket "staging.alpeware-foo-bar.appspot.com"}
                                   :http/host storage/root
                                   :file/prefix "v"
                                   :file/dir "./scripts"
                                   :storage/bucket "staging.alpeware-foo-bar.appspot.com"))))
                 (channel-rf
                  (comp
                   ssl-connection
                   (storage/files-rf
                    (comp
                     ;; one file
                     (comp
                      storage/file-rf
                      storage/session-rf
                      storage/rest-service-rf)
                     ;; upload url location
                     (ssl/request-ssl-rf http/http-rf)
                     (ssl/receive-ssl-rf json-response)
                     (fn [rf]
                       (let [upload-id (volatile! nil)]
                         (fn
                           ([] (rf))
                           ([acc] (rf acc))
                           ([acc {:storage/keys [objects bucket]
                                  :http/keys [body query-params]
                                  :keys [status headers]
                                  {:keys [location]} :headers
                                  :context/keys [parsed! done!]
                                  :as x}]
                            (when-not @upload-id
                              (prn ::location location)
                              (vreset! upload-id (-> location (string/split #"=") (last))))
                            (-> x
                                (dissoc :http/body)
                                (dissoc :http/chunks)
                                (assoc-in [:http/params :bucket] bucket)
                                (assoc-in [:http/query-params :upload-id] @upload-id)
                                (->> (rf acc)))))))

                     ;; read file into memory
                     (comp
                      storage/open-rf
                      storage/read-rf
                      storage/flip-rf
                      storage/close-rf)

                     ;; upload chunks of a file
                     (comp
                      (storage/chunks-rf
                       (comp
                        storage/rest-service-rf
                        (ssl/request-ssl-rf http/http-rf)
                        (ssl/receive-ssl-rf json-response)))
                      (drop-while (fn [{{:keys [range]} :headers
                                        :keys [status]
                                        :file/keys [size]
                                        :as x}]
                                    (prn size status (:headers x))
                                    (= status 308))))))
                   (drop-while (fn [{{:keys [range]} :headers
                                     :keys [status]
                                     :file/keys [path size]
                                     :as x}]
                                 (prn path size)
                                 path))
                   close-connection))))
               close-rf)))]
     (->> [{:context/bip-size (* 5 4096)
            :http/scheme :https
            :http/port 443
            :http/method :GET
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))

   (-> x :async/thread (.stop))
   (-> x :nio/selector (.close))

   (in-ns 'jaq.http.xrf.nio)
   *ns*

   ;; appengine
   (let [selector (selector!)
         xf (comp
             (rf/branch (fn [{:oauth2/keys [expires-in]}]
                          (> (System/currentTimeMillis) expires-in))
                        auth-rf
                        rf/identity-rf)
             attachment-rf
             channel-rf
             ssl/ssl-rf
             process-rf
             ssl/handshake-rf
             ;; app
             ;;appengine/instance-rf
             ;;appengine/list-instances-rf
             appengine/list-versions-rf
             appengine/rest-service-rf
             http/http-rf
             selector-rf
             ssl/request-ssl-rf
             ssl/response-ssl-rf
             header/response-line
             header/headers
             http/parsed-rf
             http/chunked-rf
             http/text-rf
             body-rf
             (drop-while (fn [{{:keys [content-length]} :headers}]
                           (> content-length 0)))
             ;; services
             #_(comp
                (fn [rf]
                  (let [once (volatile! false)]
                    (fn
                      ([] (rf))
                      ([acc] (rf acc))
                      ([acc {:appengine/keys [project]
                             {:keys [id]} :http/json
                             :http/keys [params]
                             :keys [headers]
                             :context/keys [parsed! done!]
                             :as x}]
                       (when-not @once
                         (parsed!)
                         (done!)
                         (prn ::app id headers)
                         (vreset! once true))
                       (-> x
                           (dissoc :http/body)
                           (dissoc :http/chunks)
                           (assoc-in [:http/params :app] id)
                           (assoc-in [:http/params :version] "v4")
                           (->> (rf acc)))))))
                ;;appengine/list-versions-rf
                ;;appengine/list-services-rf
                appengine/list-instances-rf
                appengine/rest-service-rf
                http/http-rf
                ssl/request-ssl-rf
                ssl/response-ssl-rf
                #_(map (fn [x] (prn x) x))
                header/response-line
                #_(map (fn [x] (prn x) x))
                header/headers
                http/parsed-rf
                http/chunked-rf
                http/text-rf
                body-rf))
         rf (xf (rf/result-fn))]
     (rf nil
         (merge
          {:nio/selector selector
           :context/bip-size (* 5 4096)
           :appengine/project "alpeware-foo-bar"
           ;;:http/params {:project "alpeware-foo-bar"}
           :http/params {:app "alpeware-foo-bar"
                         :service :default
                         ;;:version "1585265219180"
                         ;;:id "00c61b117c7ca8ed8affac64ee7356f65b0baf8bb4ab18810513f840a05a4ac30fc9e6c1ac50"
                         }
           :http/host appengine/root-url
           :http/scheme :https
           :http/port 443
           :http/minor 1 :http/major 1}
          oauth2))
     (let [step (partial reactor-main selector)
           start (System/currentTimeMillis)
           timeout (* 5 1000)
           steps (fn []
                   (if-let [r (rf)]
                     (def x r)
                     (when (< (System/currentTimeMillis) (+ start timeout))
                       (step)
                       (recur))))]
       (steps)
       #_step
       #_{:rf rf :step step :steps steps}))
   (def x *1)
   (-> x :http/json)

   (->> x :http/json :versions (sort-by :createTime) (reverse) (first))

   *e
   *ns*
   (in-ns 'clojure.core)
   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.nio :reload)

   (->> "/opt/jaq-http/.credentials.edn"
        (slurp)
        (clojure.edn/read-string))
   (-> "http://metadata.google.internal/computeMetadata/v1beta1/instance?recursive=true"
       (slurp)
       (clojure.data.json/read-str :key-fn keyword)
       :serviceAccounts
       (vals)
       (first)
       :email
       ((fn [email]
          (str "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/" email "/token")))
       (slurp)
       (clojure.data.json/read-str :key-fn keyword)
       ((fn [{:keys [access_token expires_in]}]
          {:oauth2/access-token access_token
           :oauth2/expires-in (->> expires_in
                                   (* 1000)
                                   (+ (System/currentTimeMillis)))})))

   (def oauth2 *1)

   (-> "http://metadata.google.internal/computeMetadata/v1beta1/instance?recursive=true"
       (slurp)
       (clojure.data.json/read-str :key-fn keyword)
       :serviceAccounts
       (vals)
       #_(first))

   (->> x :storage/objects #_(map :name) (last) :name)
   (-> x :http/json :diskUsageBytes (Integer/parseInt) (/ 1024) (/ 1024) (int))
   (->> x :http/json :versions (first))
   (->> x :http/json :locations (count))
   (->> x :http/json :locations (clojure.pprint/pprint))
   (->> x :http/json :items (first) (keys))
   (->> x :http/json :items (map :name) (first))
   (->> x :storage/items)
   (->> x :http/chunks)
   (->> x :http/req)
   (->> x :http/params)
   (->> x :http/headers)
   (->> x :http/req)
   (->> x :http/query-params)
   (->> x :headers)
   (-> x :headers :location (string/split #"=") (last))

   *e
   (->> x :status)
   (->> x :http/body)
   (->> x (filter (fn [[k v]] (contains? #{"http" "rest"} (namespace k)))) (into {}))
   (->> x (filter (fn [[k v]] (= "oauth2" (namespace k)))) (into {}))
   (->> x (map (fn [[k v]] [(keyword "oauth2" (name k)) v])) (into {}))

   (merge oauth2
          {:oauth2/client-id (->> jaq.gcp.auth/c :http/params :client-id)
           :oauth2/client-secret (->> jaq.gcp.auth/c :http/params :client-secret)})



   (->> oauth2
        (prn-str)
        (spit "/opt/jaq-http/.credentials.edn"))
   *e

   (-> oauth2 :oauth2/expires-in (- (System/currentTimeMillis)) (/ (* 60 1000)) (int))
   (->> x :oauth2/scope)
   (->> x :context/x)
   (->> x :http/params)
   (->> x :context/duration)
   (->> x :http/body (clojure.data.json/read-str))

   com.sun.nio.file.ExtendedOpenOption/DIRECT

   *e
   *ns*

   (in-ns 'clojure.core)
   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.nio :reload))
