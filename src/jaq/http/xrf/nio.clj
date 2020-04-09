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
  (.interestOps selection-key SelectionKey/OP_READ))

(defn ^SelectionKey writable! [^SelectionKey selection-key]
  (.interestOps selection-key SelectionKey/OP_WRITE))


(defn wakeup! [selection-keys]
  (->> selection-keys
       (map (fn [^SelectionKey sk]
              (.selector sk)))
       (set)
       (map (fn [^Selector e] (.wakeup e)))))

#_(defn ^SocketChannel client-channel! [^ServerSocketChannel ssc]
    (.accept ssc)
    #_(some-> (.accept ssc)
              (non-blocking)))

(defn accept! [^ServerSocketChannel server-channel]
  (.accept server-channel)
  #_(some->> server-channel
             (.accept)
             (client-channel)
             (readable selector)))

(defn connect! [^SelectionKey sk]
  ;; TODO: handle exceptions?
  (-> sk ^SocketChannel (.channel) (.finishConnect))
  #_(.interestOps sk SelectionKey/OP_WRITE))

(defn write-channel [^SocketChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn read-channel [^SocketChannel channel ^ByteBuffer buf]
  (.read channel buf))

(defn read! [^SelectionKey sk]
  (let [{;;:nio/keys [^ConcurrentLinkedDeque in]
         {{:keys [reserve commit block decommit]} :context/bip} :nio/in
         :as attachment} (.attachment sk)
        ^SocketChannel channel (.channel sk)]
    (let [bb (reserve)
          n (->> bb
                 (read-channel channel))]
      (cond
        (< n 0) ;; end of stream
        (do
          (prn ::eos)
          (.interestOps sk 0)
          (.cancel sk))

        (> n 0) ;; read some bytes
        (do
          (prn ::read n)
          (->> bb
               (.flip)
               (commit))
          sk))
      n)))

(defn write! [^SelectionKey sk]
  (let [{;;:nio/keys [^ConcurrentLinkedDeque out]
         {{:keys [reserve commit block decommit]} :context/bip} :nio/out
         :as attachment} (.attachment sk)
        ^SocketChannel channel (.channel sk)]
    (let [bb (block)]
      #_(prn ::bb bb)
      (when (.hasRemaining bb)
        (write-channel channel bb)
        #_(prn ::wrote (.position bb))
        (decommit bb))
      #_sk
      (.position bb))))

(def attachment-rf
  (fn [rf]
    (let [attachment (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [^SelectionKey selection-key]
               :as x}]
         (when-not @attachment
           (->> {:nio/in (->> [x] (into [] bip/bip-rf) (first))
                 :nio/out (->> [x] (into [] bip/bip-rf) (first))
                 :context/rf rf
                 :context/acc acc
                 :context/x x}
                (vreset! attachment))
           (some-> selection-key (.attach @attachment)))
         (->> (assoc x :nio/attachment @attachment)
              (rf acc)))))))

(def send-rf
  (fn [rf]
    (let [once (volatile! false)
          request (volatile! nil)
          requests (volatile! nil)
          clear! (fn [] (vreset! requests nil))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :nio/keys [selection-key selector attachment]
               {{{:keys [reserve commit block decommit] :as bip} :context/bip} :nio/out} :nio/attachment
               :as x}]
         (when-not @requests
           (->> req
                (map (fn [e]
                       (cond
                         (string? e)
                         (-> (.getBytes e)
                             (ByteBuffer/wrap))

                         (instance? ByteBuffer e)
                         e)))
                (vreset! requests)))
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
             #_(.put dst @request)
             (.put dst src)
             (.flip dst)
             (commit dst)
             #_(write! selection-key)
             (let [written (write! selection-key)]
               (if-not (> written 0)
                 (do
                   ;; socket buffer full so waiting to clear
                   (writable selector (.channel selection-key) (.attachment selection-key))
                   #_(.wakeup selector)
                   acc)
                 (do
                   #_(prn ::recur written)
                   (recur acc x)))))
           (do
             #_(prn ::done)
             (->> (assoc x :context/clear! clear!)
                  (rf acc)))))))))

#_(
   (in-ns 'jaq.http.xrf.nio)
   *ns*
   *e
   foo
   )

(def receive-rf
  (fn [rf]
    (let [once (volatile! false)
          parsed (volatile! false)
          parsed! (fn []
                    (vswap! parsed not))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               {{{:keys [reserve commit block decommit] :as bip} :context/bip} :nio/in} :nio/attachment
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
                                         ;;:context/done! done!
                                         :byte b)
                                  (rf acc))
                             (->> (assoc x
                                         :context/parsed! parsed!
                                         ;;:context/done! done!
                                         :char (char b))
                                  (rf acc))))))
                  (doall))
             (decommit bb))
           acc))))))

(def request-rf
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [selection-key]
               :http/keys [req]
               :context/keys [^ByteBuffer src]
               {{{:keys [reserve commit block decommit] :as bip} :context/bip} :nio/out} :nio/attachment
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
             (write! selection-key)
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
               {{{:keys [reserve commit block decommit] :as bip} :context/bip} :nio/in} :nio/attachment
               :as x}]
         (let [bb (block)]
           (when (.hasRemaining bb)
             #_(prn ::res bb)
             #_(->> bb
                    (.decode jaq.http.xrf.params/default-charset)
                    (.toString)
                    (map (fn [e] (rf acc (assoc x :char e))))
                    (dorun))
             (->> bb
                  (.limit)
                  (range)
                  (map (fn [_]
                         (let [b (-> bb (.get))]
                           (if @parsed
                             (->> (assoc x
                                         :context/parsed! parsed!
                                         ;;:context/done! done!
                                         :byte b)
                                  (rf acc))
                             (->> (assoc x
                                         :context/parsed! parsed!
                                         ;;:context/done! done!
                                         :char (char b))
                                  (rf acc))))))
                  #_(map (fn [_]
                           (let [c (-> bb (.get) (char))]
                             #_(prn c)
                             (->> c (assoc x :char) (rf acc)))))
                  (doall))
             (decommit bb))
           (rf acc)))))))

(def channel-rf
  (fn [rf]
    (let [selection-key (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :nio/keys [selector attachment]
               :as x}]
         (when-not @selection-key
           (->> (address host port)
                (channel!)
                (non-blocking)
                (register! selector attachment)
                ((fn [^SelectionKey e]
                   (.wakeup selector)
                   e))
                (vreset! selection-key)))
         (->> (assoc x :nio/selection-key ^SelectionKey @selection-key)
              (rf acc)))))))

(def bind-rf
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
                (listen! selector attachment)
                (vreset! selection-key)
                ^SelectionKey (.channel)
                (socket)
                (bind! port))
           (prn ::listening port))
         (->> (assoc x
                     :nio/server-channel ^ServerSocketChannel @server-channel
                     :nio/selection-key ^SelectionKey @selection-key)
              (rf acc)))))))

(def read-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (and (.isValid selection-key)
                  (.isReadable selection-key))
         (read! selection-key))
       (rf acc x)))))

(def write-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (and (.isValid selection-key)
                  (.isWritable selection-key))
         (write! selection-key))
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

(defn accept-rf [xf]
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [attachment
                        selector
                        ^SelectionKey selection-key
                        server-channel]
             :context/keys [src]
             :as x}]
       (when (.isAcceptable selection-key)
         (some->> server-channel
                  (accept!)
                  (non-blocking)
                  (register! selector
                             (assoc attachment
                                    :context/rf (xf (rf/result-fn))))))
       (rf acc x)))))

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

#_(def select-rf
    (fn [rf]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [selector]
               :context/keys [src]
               :as x}]
         (when (> (select! selector) 0)
           (let [^Set keys-set (.selectedKeys selector)
                 selected-keys (into #{} keys-set)]
             (.clear keys-set)
             (doseq [^SelectionKey sk selected-keys]
               (let [{:context/keys [rf acc x]
                      :as attachment} (.attachment sk)]
                 (rf acc (assoc x
                                :context/src src
                                :nio/selection-key sk
                                :nio/attachment attachment))))))
         (rf acc)))))

(def select-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [selector]
             :async/keys [stop]
             :as x}]
       (if @stop
         (rf acc x)
         (do
           (when (> (select! selector) 0)
             (let [^Set keys-set (.selectedKeys selector)
                   selected-keys (into #{} keys-set)]
               (.clear keys-set)
               (doseq [^SelectionKey sk selected-keys]
                 (let [{:context/keys [rf acc x]
                        :as attachment} (.attachment sk)]
                   (rf acc (assoc x
                                  :nio/selection-key sk
                                  :nio/attachment attachment))))))
           acc))))))

(def close-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [selector]
             :as x}]
       (prn ::closing)
       (doseq [sk (.keys selector)]
         (some-> sk (.channel) (.close))
         (.cancel sk))
       (.close selector)
       (rf acc x)))))

(defn thread-rf [xf]
  (fn [rf]
    (let [thread (volatile! nil)
          result (volatile! nil)
          stop (volatile! false)
          stop! (fn [^Selector selector]
                  (prn ::stopping @thread)
                  (vreset! stop true)
                  (.wakeup selector))
          steps (fn [rf acc x]
                  (if-let [r (rf)]
                    (vreset! result r)
                    (do
                      (rf acc x)
                      (recur rf acc x)
                      #_(when-not @stop
                          (recur rf acc x)))))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [selector]
               :as x}]
         (when-not @thread
           (->> (fj/thread
                  (-> (xf (rf/result-fn))
                      (steps acc (assoc x :async/stop stop))))
                (vreset! thread)))
         (rf acc (assoc x
                        :async/stop! (partial stop! selector)
                        :async/stop stop
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

(def process-rf
  (comp
   connect-rf
   write-rf
   read-rf))

(def connection-rf
  (comp
   http/http-rf
   selector-rf
   #_attachment-rf
   #_channel-rf
   #_ssl/ssl-rf
   #_process-rf
   #_ssl/handshake-rf
   ssl/request-ssl-rf
   ssl/response-ssl-rf
   header/response-line
   header/headers
   #_(map (fn [e] (prn ::response e) e))
   #_(drop 1)
   #_(map (fn [e] (prn ::response e) e))
   http/parsed-rf
   #_(map (fn [e] (prn ::response e) e))
   http/chunked-rf
   http/text-rf))

(def auth-rf
  (comp
   jaq.gcp.auth/refresh-rf
   (comp
    http/http-rf
    selector-rf
    attachment-rf
    channel-rf
    ssl/ssl-rf
    process-rf
    ssl/handshake-rf
    ssl/request-ssl-rf
    ssl/response-ssl-rf
    header/response-line
    header/headers
    http/parsed-rf
    http/chunked-rf
    http/text-rf)
   #_connection-rf
   (take 1)
   (map (fn [{:nio/keys [selection-key] :as x}]
          (when (.isValid selection-key)
            (prn ::cancel ::selection-key)
            (.cancel selection-key))
          x))
   (map (fn [{:http/keys [chunks] :as e}]
          (assoc e :http/body (first chunks))))
   (map (fn [{:http/keys [body] :as e}]
          (assoc e :http/json (clojure.data.json/read-str body :key-fn keyword))))
   (map (fn [{:http/keys [json] :as e}]
          (let [normalize (fn [k] (-> k (name) (string/replace #"_" "-") (keyword)))
                f (fn [[k v]] (if (keyword? k) [(normalize k) v] [k v]))]
            (->> json
                 (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)))
                 (assoc e :http/json)))))
   (map (fn [{{:keys [expires-in]} :http/json
              :as e}]
          (if expires-in
            (->> expires-in
                 (* 1000)
                 (+ (System/currentTimeMillis))
                 (assoc-in e [:http/json :expires-in]))
            e)))
   (map (fn [{:http/keys [json]
              :context/keys [request]
              :as x}]
          (->> json
               (map (fn [[k v]]
                      [(keyword "oauth2" (name k)) v]))
               (into {})
               (merge request))))))
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
              e))))
   #_(map (fn [{{:keys [items]} :http/json
                :storage/keys [objects]
                :as x}]
            (->> items
                 (into objects)
                 (assoc x :storage/objects))))))
#_(
   *e
   )

(defn process! [selected-keys]
  (doseq [^SelectionKey sk selected-keys]
    (let [{:context/keys [rf acc x]
           :as attachment} (.attachment sk)]
      (rf acc (assoc x :nio/attachment attachment)))))

(defn reactor-main [^Selector selector]
  (when (> (select! selector) 0)
    (let [^Set keys-set (.selectedKeys selector)
          selected-keys (into #{} keys-set)]
      (.clear keys-set)
      (doseq [^SelectionKey sk selected-keys]
        (let [{:context/keys [rf acc x]
               :as attachment} (.attachment sk)]
          (rf acc (assoc x :nio/attachment attachment)))))))

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

   ;; server
   (let [xf (server-rf
             (comp
              attachment-rf
              valid-rf
              read-rf
              write-rf
              receive-rf
              (rf/once-rf
               (comp header/request-line
                     header/headers
                     (map (fn [{:keys [path] :as x}]
                            (prn ::path path)
                            x))
                     (map (fn [{:http/keys [body status] :as x}]
                            (->> (assoc x
                                        :http/body "OK"
                                        :http/status 200
                                        :http/reason "OK"
                                        :http/headers {:content-type "text/plain"
                                                       :connection "keep-alive"}))))
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
                               x))))
                     send-rf))))]
     (->> [{:context/bip-size (* 1 4096)
            :http/host "localhost"
            :http/scheme :http
            :http/port 10014
            :http/path "/"
            :http/minor 1 :http/major 1
            :http/method :GET}]
          (into [] xf)))

   (def x (first *1))

   ;; repl server
   (let [response-rf (comp
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
                                 x))))
         xf (comp
             selector-rf
             (thread-rf
              (comp
               attachment-rf
               bind-rf
               (accept-rf (comp
                           attachment-rf
                           valid-rf
                           read-rf
                           write-rf
                           receive-rf
                           (rf/once-rf
                            (comp header/request-line
                                  header/headers
                                  (rf/choose-rf
                                   :path
                                   {"/repl" (comp
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
                                                                          :connection "close"}
                                                           :http/body "NOT FOUND")))})
                                  response-rf
                                  send-rf
                                  (map (fn [{:nio/keys [selection-key selector attachment] :as x}]
                                         (readable selector (.channel selection-key) attachment)
                                         #_(.cancel selection-key)
                                         x))))))
               select-rf
               close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/host "localhost"
            :http/scheme :http
            :http/port 10010
            :http/minor 1 :http/major 1}]
          (into [] xf)))

   (def x (first *1))
   *e
   *ns*

   (in-ns 'jaq.http.xrf.nio)

   (def x (first *1))

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
   (-> x (first) :async/thread (.getStackTrace) #_StackTraceElement->vec (alength))
   (->> x (first) :async/thread (.getStackTrace) clojure.reflect/reflect)
   (-> x #_(first) :nio/selector (.isOpen))

   (let [selector (-> x #_(first) :nio/selector)]
     (doseq [sk (.keys selector)]
       (some-> sk (.channel) (.close))
       (.cancel sk))
     (.close selector))

   (let [selector (selector!)
         xf (comp
             attachment-rf
             bind-rf
             (accept-rf (comp
                         attachment-rf
                         valid-rf
                         read-rf
                         write-rf
                         receive-rf
                         (rf/once-rf
                          (comp header/request-line
                                header/headers
                                (map (fn [{:keys [path] :as x}]
                                       (prn ::path path)
                                       x))
                                (map (fn [{:http/keys [body status] :as x}]
                                       (->> (assoc x
                                                   :http/body "OK"
                                                   :http/status 200
                                                   :http/reason "OK"
                                                   :http/headers {:content-type "text/plain"
                                                                  :connection "keep-alive"}))))
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
                                          x))))
                                send-rf))))
             select-rf)
         rf (xf (rf/result-fn))
         stop (volatile! false)
         stop! (fn []
                 (prn ::stopping)
                 (vreset! stop true)
                 (doseq [sk (.keys selector)]
                   (some-> sk (.channel) (.close))
                   (.cancel sk))
                 (.close selector))
         steps (fn [acc x]
                 (if-let [r (rf)]
                   (def x r)
                   (do
                     (rf acc x)
                     (when-not @stop
                       #_(prn ::recur)
                       (recur acc x)))))]
     (fj/thread
       (steps nil
              {:nio/selector selector
               :context/bip-size (* 1 4096)
               :http/host "localhost"
               :http/scheme :http
               :http/port 10010
               :http/path "/"
               :http/minor 1 :http/major 1
               :http/method :GET}))
     (def stop! stop!))

   (stop!)
   x
   *e
   *ns*

   (def t
     (fj/thread (fn []
                  (prn (Thread/activeCount))
                  :foo)))
   (-> t .getStackTrace)
   (-> t .getState)
   (Thread/activeCount)
   (-> (Thread/getAllStackTraces) keys count)

   ;; http
   (let [selector (selector!)
         xf (comp
             http/http-rf
             selector-rf
             attachment-rf
             channel-rf
             request-rf
             process-rf
             response-rf
             (comp
              #_rf/index
              header/response-line
              header/headers
              http/parsed-rf
              http/chunked-rf
              http/text-rf
              #_(map (fn [e] (prn ::response e) e))))
         rf (xf (rf/result-fn))]
     (rf nil
         {:nio/selector selector
          :http/host "jaq.alpeware.com"
          :http/scheme :http
          :http/port 80
          :http/path "/"
          :http/minor 1 :http/major 1
          :http/method :GET})
     (let [step (partial reactor-main selector)
           steps (fn []
                   (if-let [r (rf)]
                     (def x r)
                     (do
                       (step)
                       (recur))))]
       (steps)
       #_{:rf rf :step step :steps steps}))
   (def x *1)
   (-> x :headers)
   *ns*

   ;; https
   (let [selector (selector!)
         xf (comp
             http/http-rf
             selector-rf
             attachment-rf
             channel-rf
             ssl/ssl-rf
             process-rf
             ssl/handshake-rf
             ssl/request-ssl-rf
             ssl/response-ssl-rf
             #_(map (fn [e] (prn ::response e) e))
             (comp
              #_rf/index
              header/response-line
              header/headers
              (drop 1)
              http/parsed-rf
              #_(map (fn [e] (prn ::response e) e))
              http/chunked-rf
              http/text-rf
              #_(take 1)
              #_(map (fn [{:keys [body] :as x}]
                       (assoc x :body (string/join body))))
              #_(map (fn [e] (prn ::response e) e))
              (drop-while (fn [{{:keys [content-length transfer-encoding]} :headers}]
                            (and
                             (= transfer-encoding "chunked")
                             (> content-length 0))))))
         rf (xf (rf/result-fn))]
     (rf nil
         {:nio/selector selector
          :context/bip-size (* 50 4096)
          ;;:context/bip-size (* 9 4096)
          ;;:http/host "www.alpeware.com"
          ;;:http/host "www.amazon.com"
          ;;:http/host "www.reddit.com"
          ;;:http/host "www.clojure.org"
          :http/host "www.google.com"
          ;;:http/host "news.ycombinator.com"
          ;;:http/host "www.wikipedia.org"
          ;;:http/host "echo.websocket.org"
          ;;:http/headers {:connection "Upgrade" :upgrade "Websocket" :origin "https://www.websocket.org"}
          :http/scheme :https
          :http/port 443
          :http/path "/"
          :http/minor 1 :http/major 1
          :http/method :GET})
     (let [step (partial reactor-main selector)
           steps (fn []
                   (if-let [r (rf)]
                     r
                     (do
                       (step)
                       (recur))))]
       (steps)
       #_step
       #_{:rf rf :step step :steps steps}))
   (def x *1)
   (->> x :http/chunks (count))
   (->> x :http/chunks (map count))
   (->> x :http/chunks (last))
   (->> x :headers)
   (x)
   (do
     (x)
     (x))


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
             storage/files-rf
             #_(map (fn [{:file/keys [path] :as x}]
                      (prn ::path path)
                      x))
             ;; upload one file
             (rf/branch (fn [{:file/keys [path]}]
                          path)
                        (comp
                         (rf/once-rf
                          (comp
                           storage/file-rf
                           storage/session-rf
                           storage/rest-service-rf
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
                           (comp
                            (fn [rf]
                              (let [once (volatile! false)]
                                (fn
                                  ([] (rf))
                                  ([acc] (rf acc))
                                  ([acc {:storage/keys [objects bucket]
                                         :http/keys [body query-params]
                                         :keys [status headers]
                                         {:keys [location]} :headers
                                         :context/keys [parsed! done!]
                                         :as x}]
                                   (when-not @once
                                     (prn ::location location status headers body)
                                     (parsed!)
                                     (done!)
                                     (vreset! once true))
                                   #_(prn ::location location)
                                   (-> x
                                       (dissoc :http/body)
                                       (dissoc :http/chunks)
                                       (assoc-in [:http/params :bucket] bucket)
                                       (assoc-in [:http/query-params :upload-id] (-> location (string/split #"=") (last)))
                                       (->> (rf acc)))))))
                            storage/open-rf
                            storage/read-rf
                            storage/flip-rf
                            storage/close-rf
                            storage/upload-rf
                            storage/rest-service-rf
                            http/http-rf
                            (map (fn [{:context/keys [wait! go!] :as x}]
                                   (wait!)
                                   x))
                            ssl/request-ssl-rf
                            ssl/response-ssl-rf
                            (rf/once-rf
                             (comp
                              header/response-line
                              header/headers
                              http/parsed-rf
                              http/chunked-rf
                              http/text-rf
                              body-rf
                              (map (fn [{:context/keys [parsed!] :as x}]
                                     (parsed!)
                                     x))))
                            (drop-while (fn [{{:keys [range]} :headers
                                              :keys [status]
                                              :context/keys [clear! go!]
                                              :file/keys [size]
                                              :as x}]
                                          (prn size status (:headers x))
                                          (go!)
                                          (clear!)
                                          (= status 308)))
                            (map (fn [{:context/keys [wait! next!] :as x}]
                                   (wait!)
                                   (next!)
                                   x))))))
                        rf/identity-rf)
             (drop-while (fn [{:file/keys [path]
                               :keys [status]}]
                           (and (= status 200) path))))
         rf (xf (rf/result-fn))]
     (rf nil
         (merge
          {:nio/selector selector
           :context/bip-size (* 5 4096)
           ;;:file/path "./target/clojure-1.10.1.jar" ;; "./deps.edn" ;; "./target/asm-all-4.2.jar"
           :file/prefix "p/profiles"
           :file/dir "./profiles"
           ;;:http/chunk-size (* 256 1024)
           :storage/bucket "staging.alpeware-foo-bar.appspot.com"
           :http/params {;;:project "alpeware-top-9"
                         ;;:maxResults 10
                         ;;:object "apps/v1/bar/baz.json"
                         ;;:bucket "alpeware-deployments"
                         :bucket "staging.alpeware-foo-bar.appspot.com"}
           ;;:http/headers {:Connection "Keep-Alive"}
           :http/host storage/root
           :http/scheme :https
           :http/port 443
           :http/minor 1 :http/major 1}
          oauth2))
     (let [step (partial reactor-main selector)
           start (System/currentTimeMillis)
           timeout (* 60 1000)
           steps (fn []
                   (if-let [r (rf)]
                     (def x r)
                     (when (< (System/currentTimeMillis) (+ start timeout))
                       (step)
                       (recur))))]
       (steps)
       #_step
       #_{:rf rf :step step :steps steps}))

   (in-ns 'jaq.http.xrf.nio)
   (-> x :http/req)
   (-> x :rest/method)

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
   (->> (clojure.java.io/file "/opt/jaq-http")
        (file-seq)
        #_(map (fn [e] (.path e)))
        (take 10))

   *e
   (-> oauth2 :oauth2/expires-in (- (System/currentTimeMillis)) (/ (* 60 1000)) (int))
   (->> x :oauth2/scope)
   (->> x :context/x)
   (->> x :http/params)
   (->> x :context/duration)
   (->> x :http/body (clojure.data.json/read-str))

   com.sun.nio.file.ExtendedOpenOption/DIRECT
   (require 'clojure.data.json)

   *e
   *ns*

   (in-ns 'clojure.core)
   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.nio :reload)


   (into []
         (comp
          jaq.gcp.storage/service-rf
          jaq.gcp.storage/list-buckets-rf
          jaq.gcp.storage/rest-rf
          jaq.gcp.storage/auth-rf)
         [x])
   (def y *1)
   (keys y)
   (->> y :http/host)

   (let [xf (comp
             jaq.gcp.storage/service-rf
             jaq.gcp.storage/list-buckets-rf
             jaq.gcp.storage/rest-rf
             jaq.gcp.storage/auth-rf)
         rf (xf (rf/result-fn))]
     (rf nil y)
     (rf))

   (let [xf (comp
             (map (fn [e] e)))
         rf (xf (rf/result-fn))]
     (rf nil y)
     (rf))


   *e
   (def steps *1)

   (steps)

   (jaq.gcp.storage/buckets {:oauth2/access-token (:access-token c)
                             :params/project "alpeware-foo-bar"})

   (in-ns 'jaq.http.xrf.nio)

   *e)
