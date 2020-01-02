(ns jaq.http.client.nio
  (:require
   [clojure.string :as string]
   [taoensso.tufte :as tufte :refer [defnp fnp]]
   [jaq.async.fj :as fj]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.io IOException]
   [java.net InetSocketAddress ServerSocket Socket SocketAddress InetSocketAddress]
   [java.nio.charset StandardCharsets Charset]
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [java.util Set]
   [java.util.concurrent ConcurrentLinkedDeque]
   [javax.net.ssl
    SNIHostName SNIServerName
    SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status
    SSLContext SSLSession]))

(set! *warn-on-reflection* true)

(def stats-accumulator (tufte/add-accumulating-handler! {:ns-pattern "*"}))

(def ^:dynamic *http-client* nil)

(def ^:dynamic *client-xrf* nil)

(def socket-buffer-size (* 16 1024))
(def buffer-size (* 32 1024))

(def ^Charset charset StandardCharsets/UTF_8)

(defn address [^String host ^Integer port]
  (InetSocketAddress. host port))

(defn non-blocking [^AbstractSelectableChannel channel]
  (.configureBlocking channel false))

(defn client-socket [^Socket socket]
  (doto socket
    (.setTcpNoDelay true)
    (.setReceiveBufferSize socket-buffer-size)
    (.setSendBufferSize socket-buffer-size)
    (.setReuseAddress true)))

(defn ^Selector selector! [] (Selector/open))

(defn select! [^Selector selector]
  (.select selector))

(defn ^SelectionKey readable [^Selector selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_READ))

(defn ^SelectionKey writable [^Selector selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_WRITE))

(defn ^SelectionKey connectable [^Selector selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_CONNECT))

(defn ^SocketChannel channel [^SocketAddress socket-address]
  (SocketChannel/open socket-address))

(defn write-channel [^SocketChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn read-channel [^SocketChannel channel ^ByteBuffer buf]
  (.read channel buf))

(defnp register! [^Selector selector attachment ^SocketChannel channel]
  (.register channel
             selector
             (bit-or SelectionKey/OP_CONNECT SelectionKey/OP_WRITE SelectionKey/OP_READ)
             attachment))

(defnp wakeup! [selection-keys]
  (->> selection-keys
       (map (fn [^SelectionKey sk]
              (.selector sk)))
       (set)
       (map (fnp [^Selector e] (.wakeup e)))))

(defnp read! [^ByteBuffer read-buffer ^SelectionKey sk]
  (let [{:keys [state engine ^ConcurrentLinkedDeque in] :as attachment} (.attachment sk)
        ^SocketChannel channel (.channel sk)]
    (let [n (->> read-buffer
                 (.clear)
                 (read-channel channel))]
      (.flip read-buffer)
      (cond
        (< n 0) ;; end of stream
        (do
          (.interestOps sk 0)
          (.cancel sk))

        (> n 0) ;; read some bytes
        (let [bb (ByteBuffer/allocate n)
              #_bb #_(->> plain
                          ^CharBuffer (. charset decode)
                          (.asReadOnlyBuffer))]
          (prn ::read-buffer read-buffer n)
          (.put bb read-buffer)
          (.flip bb)
          (.addLast in bb)
          #_(->> (assoc attachment
                        :in bb
                        :state :decode)
                 (.attach sk))
          sk)))))

(defnp write! [^SelectionKey sk]
  (let [{:keys [^ConcurrentLinkedDeque out state] :as attachment} (.attachment sk)
        ^SocketChannel channel (.channel sk)]
    (when-not (.isEmpty out) #_(and out (.isValid channel-key) (.isOpen channel))
              (let [^ByteBuffer buf (.peekFirst out)
                    n (write-channel channel buf)
                    r (.remaining buf)]
                (prn ::wrote n)
                (if (= r 0) ;; end of buf
                  (do
                    (.removeFirst out)
                    #_(.interestOps sk SelectionKey/OP_READ)
                    #_(-> sk (.selector) (.wakeup))
                    sk)

                  (do
                    #_(.interestOps sk SelectionKey/OP_WRITE)
                    #_(-> sk (.selector) (.wakeup))
                    sk))))))

(defnp connect! [^SelectionKey sk]
  ;; TODO: handle exceptions?
  (-> sk ^SocketChannel (.channel) (.finishConnect))
  (.interestOps sk SelectionKey/OP_WRITE))

(def handshake-status
  {SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING :not-handshaking
   SSLEngineResult$HandshakeStatus/FINISHED :finished
   SSLEngineResult$HandshakeStatus/NEED_TASK :need-task
   SSLEngineResult$HandshakeStatus/NEED_WRAP :need-wrap
   SSLEngineResult$HandshakeStatus/NEED_UNWRAP :need-unwrap
   SSLEngineResult$HandshakeStatus/NEED_UNWRAP_AGAIN :need-unwrap-again})

(defn clarify [hs]
  (get {:need-wrap :encode
        :need-unwrap :decode
        :need-unwrap-again :decode-again}
       hs hs))

(def engine-status
  {SSLEngineResult$Status/BUFFER_OVERFLOW :buffer-overflow
   SSLEngineResult$Status/BUFFER_UNDERFLOW :buffer-underflow
   SSLEngineResult$Status/CLOSED :closed
   SSLEngineResult$Status/OK :ok})

(defnp handshake? [^SSLEngine engine]
  (->> ^SSLEngineResult$HandshakeStatus (.getHandshakeStatus engine)
       (get handshake-status)))

(defnp result? [^SSLEngineResult result]
  (->> ^SSLEngineResult$Status (.getStatus result)
       (get engine-status)))

#_(

   (-> c .attachment :engine handshake? clarify)

   )

(def ^ByteBuffer empty-buffer (ByteBuffer/allocate 0))

(defnp handshake!
  ([^SSLEngine engine ^SelectionKey sk]
   (handshake! engine sk (.getHandshakeStatus engine)))
  ([^SSLEngine engine ^SelectionKey sk
    ^SSLEngineResult$HandshakeStatus handshake-status]
   (let [{:keys [^ConcurrentLinkedDeque in ^ByteBuffer encoded
                 ^ConcurrentLinkedDeque out ^ByteBuffer decoded
                 ^ByteBuffer scratch
                 ^ByteBuffer request]
          :as attachment} (.attachment sk)
         hs (handshake? engine)
         _ (prn ::hs hs)
         step (condp = hs
                :finished
                (do
                  #_(->> (assoc attachment
                                :status :connected)
                         (.attach sk))
                  :finished)

                :need-task
                (do
                  (prn ::executing ::task)
                  (-> (.getDelegatedTask engine)
                      ^Runnable (.run))
                  (handshake? engine))

                ;; write data to network
                :need-wrap
                (let [_ (.clear scratch)
                      result (-> engine
                                 (.wrap empty-buffer scratch)
                                 (result?))]
                  (condp = result
                    :buffer-overflow
                    :tbd
                    :buffer-underflow
                    :tbd
                    :closed
                    :tbd
                    :ok
                    (do
                      (.flip scratch)
                      (.addLast out
                                (-> (.limit scratch)
                                    (ByteBuffer/allocate)
                                    (.put scratch)
                                    (.flip)))
                      (prn ::scratch scratch)
                      #_(.interestOps sk SelectionKey/OP_WRITE)
                      (handshake? engine))))

                ;; read data from network
                :need-unwrap
                (let [^ByteBuffer buf (.peekFirst in)]
                  (if #_(and in (< (.position in) (.limit in)))
                      (and buf (< (.position buf) (.limit buf)))
                      (let [result (-> engine
                                       (.unwrap buf empty-buffer)
                                       (result?))]
                        (condp = result
                          :buffer-overflow
                          :tbd
                          :buffer-underflow
                          :tbd
                          :closed
                          :tbd
                          :ok
                          (do
                            (when-not (.hasRemaining buf)
                              (.removeFirst in))
                            (prn ::in buf)
                            #_(.interestOps sk SelectionKey/OP_READ)
                            (handshake? engine))))
                      :waiting-for-input))

                ;; read data to network
                ;; TODO: can we remove this case?
                :need-unwrap-again
                (do
                  (prn ::unwrap-again)
                  :tbd)
                #_(let [result (-> engine
                                   (.unwrap in decoded)
                                   (result?))]
                    (condp = result
                      :buffer-overflow
                      :tbd
                      :buffer-underflow
                      :tbd
                      :closed
                      :tbd
                      :ok
                      (do
                        (.interestOps sk SelectionKey/OP_READ)
                        (handshake? engine))))
                :noop)]
     (prn ::step step ::in in ::out out)
     ;; TODO: fix
     #_(when (contains? #{:finished :not-handshaking} step)
         ;; handshake is done, so queue our actual request
         (let [_ (.clear scratch)
               result (-> engine
                          (.wrap request scratch)
                          (result?))]
           (condp = result
             :buffer-overflow
             :tbd
             :buffer-underflow
             :tbd
             :closed
             :tbd
             :ok
             (do
               (.flip scratch)
               (.addLast out scratch)
               (prn ::out scratch)
               #_(.interestOps sk SelectionKey/OP_WRITE)
               (prn (handshake? engine))))))
     (let [^ByteBuffer buf-in (.peekFirst in)
           ^ByteBuffer buf-out (.peekFirst out)]
       (if-not (or
                (= step :need-task)
                #_(and buf-out (= step :need-wrap) (= (.limit buf-out) (.capacity buf-out)))
                (= step :need-wrap)
                (= step :need-unwrap)
                #_(and buf-in (= step :need-unwrap) (< (.position buf-in) (.limit buf-in))))
         step
         ;; TODO: fork as new task?
         (handshake! engine sk (.getHandshakeStatus engine)))))))

#_(
   c
   (def e (-> c .attachment :engine))
   (write-channel (-> c .channel) (-> c .attachment :request))
   (.interestOps c SelectionKey/OP_WRITE)
   (.wakeup s)
   (-> e (handshake?) (clarify))

   (.wrap e
          (-> c .attachment :encoded)
          (-> c .attachment :out))

   (-> c .attachment :in (.position))


   )
(defnp process! [selected-keys]
  (prn ::processing selected-keys)
  (doseq [^SelectionKey sk selected-keys]
    (let [{:keys [^ConcurrentLinkedDeque in ^ConcurrentLinkedDeque out
                  ^ByteBuffer encoded ^ByteBuffer decoded
                  ^ByteBuffer scratch ^ByteBuffer request
                  callback-fn
                  scheme
                  ^SSLEngine engine
                  state
                  xf]
           :as attachment} (.attachment sk)
          hs (-> engine (handshake?))]
      (try
        (if-not (contains? #{:finished :not-handshaking} hs)
          (handshake! engine sk)
          (cond

            (.hasRemaining request)
            (let [_ (.clear scratch)
                  result (-> engine
                             (.wrap request scratch)
                             (result?))]
              (condp = result
                :buffer-overflow
                :tbd
                :buffer-underflow
                :tbd
                :closed
                :tbd
                :ok
                (do
                  (.flip scratch)
                  (.addLast out scratch)
                  (prn ::out scratch)
                  #_(.interestOps sk SelectionKey/OP_WRITE)
                  (prn (handshake? engine)))))

            (not (.isEmpty in))
            (let [_ (.clear scratch)
                  ^ByteBuffer buf (.peekFirst in)
                  result (-> engine
                             (.unwrap buf scratch)
                             (result?))]
              (prn ::decoded scratch)
              sk)

            :process
            (do
              (let [;;xf (or xf (*client-xrf* (rf/result-fn)))
                    ]
                ;; TODO: split into sub-tasks based on size of input buf
                (run! (fn [x] (xf nil x)) in)
                #_(tufte/p ::xf
                           (run! (fn [x] (xf nil x)) in))
                (if-let [buf (some-> (xf))]
                  (do ;; enough input to produce a response
                    (->> (fn []
                           (callback-fn buf)
                           (fj/task)
                           (fj/fork)))
                    (.interestOps sk 0)
                    (.cancel sk)
                    #_(-> sk (.selector) (.wakeup)))
                  (do ;; need more input so store current xf state
                    (->> {:state :reading}
                         (conj attachment)
                         (.attach sk))
                    (.interestOps sk SelectionKey/OP_READ)))))))
        (catch ClosedChannelException _
          #_(prn ::closed e sk))
        (catch CancelledKeyException _
          #_(prn ::cancelled e sk))))))

(defnp process-keys! [selected-keys]
  ;; TODO: Dynamically determine batch size
  (let [batch-size 400]
    (->> selected-keys
         (partition batch-size batch-size [])
         (map (fn [block]
                (if (< (count block) batch-size)
                  (process! block)
                  (-> (fn [] (process! block))
                      #_(fj/invoke)
                      (fj/task)
                      (fj/fork)))))
         (doall))
    selected-keys))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   )

(defnp keys! [^ByteBuffer read-buffer
              selected-keys
              ^SelectionKey sk]
  (or
   (some->>
    ;; TODO: use ready set directly
    (try
      #_(cond
          (.isConnectable sk)
          (connect! sk)

          (.isReadable sk)
          (read! read-buffer sk)

          (.isWritable sk)
          (write! sk))

      (when (.isConnectable sk)
        (connect! sk))

      (when (.isReadable sk)
        (read! read-buffer sk))

      (when (.isWritable sk)
        (write! sk))

      sk
      (catch CancelledKeyException _
        nil))
    (conj selected-keys))
   selected-keys))

;; TODO: fork multiple selectors
;; TODO: extract reducing fn
(defnp reactor-main [^ByteBuffer read-buffer
                     ^Selector selector]
  (when (> (select! selector) 0)
    (let [^Set keys-set (.selectedKeys selector)
          ready-set (into #{} keys-set)
          _ (.clear keys-set)]
      (->> ready-set (reduce (partial keys! read-buffer) [])))))

#_(
   *e
   )

(defnp event-loop [^Selector selector]
  (let [shutdown (volatile! false)
        shutdown-fn (fn [] (vreset! shutdown true) (.wakeup selector))]
    (alter-var-root
     #'*http-client*
     (constantly
      {:selector selector
       :shutdown-fn shutdown-fn
       :event-loop
       (fj/thread
         (let [read-buffer (ByteBuffer/allocateDirect buffer-size)]
           (prn ::client ::event ::loop)
           (loop []
             (when-not @shutdown
               (some->>
                (reactor-main read-buffer selector)
                (process-keys!)
                (wakeup!)
                (dorun))
               #_(tufte/profile
                  {:id :client}
                  (some->>
                   (reactor-main read-buffer selector)
                   (process-keys!)
                   (wakeup!)
                   (dorun)))
               (recur)))
           (try
             (prn ::accept ::shutdown)
             (.close selector)
             (catch IOException e
               (prn ::shutdown e)))
           (prn "---- stats ----")
           (println (tufte/format-grouped-pstats @stats-accumulator))))}))))

(defn channel! [^Selector selector ^String host ^Integer port attachment]
  (->> (address host port)
       (channel)
       (non-blocking)
       #_(connectable selector)
       (register! selector attachment)
       ((fn [^SelectionKey e]
          (.wakeup selector)
          e))))

;; SSL
(defn ^SSLContext context []
  (SSLContext/getDefault)
  #_(doto (SSLContext/getInstance "TLSv1.2")
      (.init nil nil nil)))

(defn ^SSLEngine engine [^SSLContext context] (.createSSLEngine context))

(defn ^SSLEngine client-mode [^SSLEngine engine]
  (doto engine (.setUseClientMode true)))

;; aka encode: plain src -> encoded dst
(defnp wrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.wrap engine src dst)]))

;; aka decode: encoded src -> plain dst
(defnp unwrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.unwrap engine src dst)]))


(defn encode! [^SSLEngine engine])

#_(
   ;; network buffer size
   (-> (context) (engine) (client-mode) (.getSession) (.getPacketBufferSize))
   ;; application buffer size
   (-> (context) (engine) (client-mode) (.getSession) (.getApplicationBufferSize))

   SSLEngineResult$HandshakeStatus/FINISHED
   )

(defn configure [^SSLEngine engine ^String host]
  (let [params (.getSSLParameters engine)
        ^SNIServerName server-name (SNIHostName. host)]
    (.setServerNames params [server-name])
    (.setSSLParameters engine params)
    engine))

(defn request [selector {:keys [scheme host port path req]
                         :or {scheme :http path "/"}}]
  (let [m {:http 80 :https 443}
        port (or port (get m scheme))
        ^SSLEngine engine (when (= scheme :https)
                            (-> (context) (engine) (client-mode) (configure host)))
        packet-buffer-size (-> engine (.getSession) (.getPacketBufferSize))
        encoded (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        decoded (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        scratch (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        in (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        out (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        ;;request (ByteBuffer/wrap (.getBytes (str "GET " path " HTTP/1.1\r\nHost: " host "\r\n\r\n")))
        request (->> req (clojure.string/join) (.getBytes) (ByteBuffer/wrap))
        ]
    ;; write out handshake
    (.beginHandshake engine)
    (.wrap engine encoded out)
    (.flip out)
    ;;
    (channel! selector host port
              {:request request
               :encoded encoded
               :decoded decoded
               :scratch scratch
               :in (ConcurrentLinkedDeque.)
               :out (ConcurrentLinkedDeque. [out])
               :engine engine
               :scheme scheme
               :callback-fn (fn [b] (prn ::b b))
               :xf ((comp rf/index
                          header/response-line
                          header/headers
                          (map (fn [x] (prn x) x))
                          (drop-while (fn [_] true))) (rf/result-fn))})))

#_(
   *ns*
   *e
   (in-ns 'clojure.core)
   (require 'jaq.http.client.nio :reload)
   (in-ns 'jaq.http.client.nio)

   (->> (ConcurrentLinkedDeque. [:foo :bar]) (.isEmpty))

   (-> *http-client* :shutdown-fn (apply []))
   (.close s)
   (-> c (.channel) (.close))
   (-> c (.channel))
   (-> c (.cancel))

   (def s (selector!))
   (event-loop s)
   (def c (channel! s "google.com" 80 {:out (ByteBuffer/wrap (.getBytes "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
                                       :xf ((map (fn [x] x)) (rf/result-fn))
                                       :callback-fn (fn [b] (prn ::b b))}))

   (.wakeup s)
   (def host "www.googleapis.com")
   (def path "/storage/v1/b?project=alpeare-jaq-runtime")

   ;; google oauth2
   (def google-client-id "32555940559.apps.googleusercontent.com")
   (def google-client-secret "ZmssLNjJy2998hD4CTg2ejr2")
   (def auth-uri "https://accounts.google.com/o/oauth2/auth")
   (def token-uri "https://accounts.google.com/o/oauth2/token")
   (def revoke-uri "https://accounts.google.com/o/oauth2/revoke")
   (def local-redirect-uri "urn:ietf:wg:oauth:2.0:oob")
   (def cloud-scopes ["https://www.googleapis.com/auth/appengine.admin" "https://www.googleapis.com/auth/cloud-platform"])
   {:access-type "offline"
    :prompt "consent"
    :include-granted-scopes "true"
    :response-type "code"
    :scope (clojure.string/join " " cloud-scopes)}

   ;; accounts.google.com/o/oauth2/auth?client_id=32555940559.apps.googleusercontent.com&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&access_type=offline&prompt=consent&include_granted_scopes=true&response_type=code&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fappengine.admin+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform

   ;; request api
   (def c
     (->> {:host "accounts.google.com" :path "/o/oauth2/token"
           ;;:host "jaq.alpeware.com" :path "/"
           :method :POST :scheme :https :port 443
           :minor 1 :major 1
           :headers {:content-type "application/x-www-form-urlencoded"}
           :params {:client-id google-client-id
                    :client-secret google-client-secret
                    :redirect-uri local-redirect-uri
                    :code "4/twGly8_B-5JFAzujY8m2mxeU9PoWB7QxjqI62WeivHihbvEjBrs5Bjk"
                    :grant-type "authorization_code"
                    ;;:access-type "offline"
                    ;;:prompt "consent"
                    ;;:include-granted-scopes "true"
                    ;;:response-type "code"
                    ;;:scope (clojure.string/join " " cloud-scopes)
                    }}
          (conj [])
          (sequence
           (comp
            (map (fn [x] (assoc x :req [])))
            (map (fn [{:keys [req headers host] :as x}]
                   (assoc x :headers (conj {:Host host} headers))))
            (map (fn [{:keys [req method] :as x}]
                   (update x :req conj (-> method (name) (str)))))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj " ")))
            (map (fn [{:keys [req path] :as x}]
                   (update x :req conj path)))
            (fn [rf]
              (let [normalize (fn [s] (clojure.string/replace s #"-" "_"))]
                (fn params
                  ([] (rf))
                  ([acc] (rf acc))
                  ([acc {:keys [req method params] :as x}]
                   (if (and (= :GET method) params)
                     (->> params
                          (reduce
                           (fn [reqs [k v]]
                             (conj reqs
                                   (->> k (name) (str) (normalize) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                   "="
                                   (->> v (str) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                   "&"))
                           ["?"])
                          (butlast)
                          (update x :req into)
                          (rf acc))
                     (rf acc x))))))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj " ")))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj "HTTP")))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj "/")))
            (map (fn [{:keys [req major minor] :as x}]
                   (update x :req conj (str major "." minor))))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj "\r\n")))
            (fn [rf]
              (let [normalize (fn [s] (clojure.string/replace s #"-" "_"))]
                (fn params
                  ([] (rf))
                  ([acc] (rf acc))
                  ([acc {:keys [method params body]
                         :as x}]
                   (if (and (= :POST method) params)
                     (->> params
                          (reduce
                           (fn [bodies [k v]]
                             (conj bodies
                                   (->> k (name) (str) (normalize) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                   "="
                                   (->> v (str) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                   "&"))
                           [])
                          (butlast)
                          (clojure.string/join)
                          (assoc x :body)
                          (rf acc))
                     (rf acc x))))))
            (map (fn [{:keys [headers body] :as x}]
                   (update x :headers conj {:content-length (count body)})))
            (fn [rf]
              (fn headers
                ([] (rf))
                ([acc] (rf acc))
                ([acc {:keys [req headers] :as x}]
                 (if headers
                   (->> headers
                        (reduce
                         (fn [reqs [k v]]
                           (conj reqs
                                 (->> k (name) (str) (string/capitalize))
                                 ": "
                                 (->>
                                  (cond
                                    (instance? clojure.lang.Keyword v)
                                    (name v)
                                    :else
                                    v)
                                  (str))
                                 "\r\n"))
                         [])
                        (update x :req into)
                        (rf acc))
                   (rf acc x)))))
            (map (fn [{:keys [req] :as x}]
                   (update x :req conj "\r\n")))
            (map (fn [{:keys [req body] :as x}]
                   (update x :req conj body)))
            #_(map :req)
            #_(fn [rf]
                (fn method
                  ([] (rf))
                  ([acc] (rf acc))
                  ([acc {:keys [method req] :as x}]
                   (rf acc (assoc x :req (-> method (name) (str " ")))))))))
          (first)
          #_:body
          #_:req
          (request s)
          #_(clojure.string/join))
     )

   *e
   (reduce
    (fn [reqs [k v]]
      (conj reqs (-> k name str) (str v)))
    []
    {:foo :bar :baz :barrz})

   (def c (request s {:host "accounts.google.com" :path "/o/oauth2/auth" :scheme :https :port 443}))

   (def c (request s {:host "jaq.alpeware.com" :path "/" :scheme :https :port 443}))

   (def c (request s {:host host :path path :scheme :https :port 443}))
   (-> c (.channel) (.close))
   (.cancel c)
   (def e (-> c .attachment :engine))

   (write-channel (-> c .channel) (-> c .attachment :request))
   (.interestOps c SelectionKey/OP_WRITE)
   (.wakeup s)
   (-> e (handshake?) #_(clarify))
   (-> e (.getSSLParameters) (.getServerNames))

   (-> e (.getHandshakeSession))
   (-> e (.getSession) (.isValid))

   (configure e host)
   (->> e (.getEnabledProtocols) (map str))

   (-> c .attachment :decoded)
   (-> c .attachment :decoded (.rewind))
   (-> c .attachment :decoded (.flip))
   (->> c .attachment :decoded (.decode params/default-charset) (.toString))
   (def r *1)

   (sequence
    (comp
     rf/index
     header/response-line
     header/headers
     (take 1)
     )
    r)

   ;; json
   (->>
    (sequence
     (comp
      rf/index
      header/response-line
      header/headers
      (drop 1)
      (fn [rf]
        (let [vacc (volatile! [])
              done (volatile! false)
              val (volatile! nil)
              k :content-length
              assoc-fn (fn [acc x]
                         (->> @val
                              (update x :headers conj)
                              (rf acc)))]
          (fn chunk
            ([] (rf))
            ([acc] (rf acc))
            ([acc {:keys [char]
                   {:keys [transfer-encoding]} :headers
                   :as x}]
             (if (= "chunked" transfer-encoding)
               (cond
                 @done
                 (assoc-fn acc x)

                 (and
                  (nil? @val)
                  (contains? #{\return \newline} char))
                 (do
                   (prn @vacc)
                   (vreset! val
                            {k
                             (-> (apply str @vacc)
                                 (Integer/parseInt 16))})
                   (vreset! vacc nil)
                   (vreset! done true)
                   (rf acc))

                 :else
                 (do
                   (vswap! vacc conj char)
                   (rf acc)))
               (rf acc x))))))
      (drop 1)
      (json/decoder)
      (json/process)
      (take 1))
     r)
    (first)
    :json)

   *e



   params/default-charset
   (-> c .attachment :scratch (.clear))
   (.wrap e
          empty-buffer
          (-> c .attachment :scratch))

   (.wrap e
          (-> c .attachment :request)
          (-> c .attachment :scratch))

   (.clear (-> c .attachment :scratch))

   (.flip (-> c .attachment :scratch))

   (write-channel (-> c .channel) (-> c .attachment :scratch))
   (read-channel (-> c .channel) (-> c .attachment :out))

   *e


   (->> c .attachment :scratch (.flip))
   (->> c .attachment :scratch (. charset decode) (.toString))
   (def r *1)

   (.unwrap e
            empty-buffer
            (-> c .attachment :scratch))

   (-> c .attachment :decoded (.rewind))
   (->> c .attachment :decoded (. charset decode))

   (-> (.getDelegatedTask e) (.run))
   (-> e (handshake?) (clarify))

   (->> c .attachment :request (.rewind) (. charset decode))
   (-> c .attachment :engine (.getHandshakeStatus))
   (-> c .attachment keys)
   (->> c .attachment :in (. charset decode))
   (->> c .attachment :in )

   (def b (ByteBuffer/allocate 20000))
   (def bb (ByteBuffer/allocate 20000))
   (-> c .attachment :engine (.wrap (ByteBuffer/wrap (.getBytes "")) b))
   (-> c .attachment :engine (.unwrap b bb))

   *e

   (-> c (.channel) (.isConnected))
   (-> c (.channel) (.close))
   (-> c (.cancel))
   (-> c (.attachment) :in (.toString))
   (def b *1)
   (-> c (connect!))
   (wakeup! [c])
   c
   (.selectNow s)
   *e)
