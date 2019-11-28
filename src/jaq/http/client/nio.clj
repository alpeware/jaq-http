(ns jaq.http.client.nio
  (:require
   [taoensso.tufte :as tufte :refer [defnp fnp]]
   [jaq.async.fj :as fj]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.header :as header]
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
             (bit-or SelectionKey/OP_CONNECT SelectionKey/OP_WRITE)
             attachment))

(defnp wakeup! [selection-keys]
  (->> selection-keys
       (map (fn [^SelectionKey sk]
              (.selector sk)))
       (set)
       (map (fnp [^Selector e] (.wakeup e)))))

(defnp read! [^ByteBuffer read-buffer ^SelectionKey sk]
  (let [{:keys [state engine in] :as attachment} (.attachment sk)
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
          (->> (assoc attachment
                      :in bb
                      :state :decode)
               (.attach sk))
          sk)))))

(defnp write! [^SelectionKey sk]
  (let [{:keys [^ByteBuffer out state] :as attachment} (.attachment sk)
        ^SocketChannel channel (.channel sk)]
    (prn ::write out)
    (when out #_(and out (.isValid channel-key) (.isOpen channel))
          (let [n (write-channel channel out)
                r (.remaining out)]
            (prn ::wrote n)
            (if (= r 0) ;; end of buf
              (do
                (.clear out)
                (.interestOps sk SelectionKey/OP_READ)
                #_(-> sk (.selector) (.wakeup))
                sk)

              (do
                (.interestOps sk SelectionKey/OP_WRITE)
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

(defnp handshake!
  ([^SSLEngine engine ^SelectionKey sk]
   (handshake! engine sk (.getHandshakeStatus engine)))
  ([^SSLEngine engine ^SelectionKey sk
    ^SSLEngineResult$HandshakeStatus handshake-status]
   (let [{:keys [^ByteBuffer in ^ByteBuffer encoded
                 ^ByteBuffer out ^ByteBuffer decoded]
          :as attachment} (.attachment sk)
         hs (handshake? engine)
         _ (prn ::hs hs)
         step (condp = hs
                :finished
                (do
                  (->> (assoc attachment
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
                (let [_ (.clear out)
                      result (-> engine
                                 (.wrap encoded out)
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
                      (.flip out)
                      (prn ::out out)
                      (.interestOps sk SelectionKey/OP_WRITE)
                      (handshake? engine))))

                ;; read data from network
                :need-unwrap
                (if (and in (< (.position in) (.limit in)))
                  (let [result (-> engine
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
                        ;; TODO: clear in from attachment?
                        (prn ::in in)
                        (.interestOps sk SelectionKey/OP_READ)
                        (handshake? engine))))
                  :waiting-for-input)

                ;; read data to network
                :need-unwrap-again
                (let [result (-> engine
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
     (if-not (or
              (= step :need-task)
              (and (= step :need-wrap) (= (.limit out) (.capacity out)))
              (and (= step :need-unwrap) (< (.position in) (.limit in))))
       step
       ;; TODO: fork as new task?
       (handshake! engine sk (.getHandshakeStatus engine))))))

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
  (doseq [^SelectionKey sk selected-keys]
    (let [{:keys [^ByteBuffer in ^ByteBuffer out
                  ^ByteBuffer encoded ^ByteBuffer decoded
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
          (condp = state
            :decode
            (let [result (-> engine
                             (.unwrap in decoded)
                             (result?))]
              (prn ::decoded decoded)
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
                    (.interestOps sk SelectionKey/OP_READ)))))
            :noop))
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
      (cond
        (.isConnectable sk)
        ;;TODO: connect
        (connect! sk)

        (.isReadable sk)
        (read! read-buffer sk)

        (.isWritable sk)
        (write! sk))
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

(defn configure [^SSLEngine engine host]
  (let [params (.getSSLParameters engine)
        ^SNIServerName server-name (SNIHostName. host)]
    (.setServerNames params [server-name])
    (.setSSLParameters engine params)
    engine))

(defn request [selector {:keys [scheme host port path]
                         :or {scheme :http path "/"}}]
  (let [m {:http 80 :https 443}
        port (or port (get m scheme))
        engine (when (= scheme :https)
                 (-> (context) (engine) (client-mode) (configure host)))
        packet-buffer-size (-> engine (.getSession) (.getPacketBufferSize))
        encoded (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        decoded (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        in (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        out (-> (ByteBuffer/allocateDirect packet-buffer-size) (.clear))
        request (ByteBuffer/wrap (.getBytes (str "GET " path " HTTP/1.1\r\nHost: " host "\r\n\r\n")))]
    ;; write out handshake
    (.beginHandshake engine)
    (.wrap engine encoded out)
    (.flip out)
    ;;
    (channel! selector host port
              {:request request
               :encoded encoded
               :decoded decoded
               :in nil
               :out out
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

   (-> *http-client* :shutdown-fn (apply []))
   (.close s)
   (-> c (.channel) (.close))
   (-> c (.channel))

   (def s (selector!))
   (event-loop s)
   (def c (channel! s "google.com" 80 {:out (ByteBuffer/wrap (.getBytes "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))
                                       :xf ((map (fn [x] x)) (rf/result-fn))
                                       :callback-fn (fn [b] (prn ::b b))}))

   (def host "www.googleapis.com")
   (def path "/storage/v1/b?project=alpeare-jaq-runtime")

   (def c (request s {:host host :path path :scheme :https :port 443}))
   (def e (-> c .attachment :engine))

   (write-channel (-> c .channel) (-> c .attachment :request))
   (.interestOps c SelectionKey/OP_WRITE)
   (.wakeup s)
   (-> e (handshake?) (clarify))
   (-> e (.getSSLParameters) (.getServerNames))

   (-> e (.getHandshakeSession))
   (-> e (.getSession) (.isValid))

   (configure e host)
   (->> e (.getEnabledProtocols) (map str))

   (-> c .attachment :decoded)

   (-> c .attachment :out (.clear))
   (.wrap e
          (-> c .attachment :request)
          (-> c .attachment :out))

   (.clear (-> c .attachment :out))

   (.flip (-> c .attachment :out))

   (write-channel (-> c .channel) (-> c .attachment :out))
   (read-channel (-> c .channel) (-> c .attachment :out))

   *e


   (.unwrap e
            (-> c .attachment :in)
            (-> c .attachment :decoded))

   (-> (.getDelegatedTask e) (.run))
   (-> e (handshake?) (clarify))

   (-> c .attachment :out)
   (-> c .attachment :engine (.getHandshakeStatus))
   (-> c .attachment keys)
   (->> c .attachment :in (. charset decode))
   (->> c .attachment :in )

   (def b (ByteBuffer/allocate 20000))
   (def bb (ByteBuffer/allocate 20000))
   (-> c .attachment :engine (.wrap (ByteBuffer/wrap (.getBytes "")) b))
   (-> c .attachment :engine (.unwrap b bb))

   c

   b


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
   *e
   )
