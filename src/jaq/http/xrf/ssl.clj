(ns jaq.http.xrf.ssl
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.params :as params])
  (:import
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [javax.net.ssl
    SNIHostName SNIServerName
    SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status
    SSLContext SSLSession SSLException]
   [java.util.concurrent ConcurrentLinkedDeque]))

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

(defn handshake? [^SSLEngine engine]
  (->> ^SSLEngineResult$HandshakeStatus (.getHandshakeStatus engine)
       (get handshake-status)))

(defn result? [^SSLEngineResult result]
  (->> ^SSLEngineResult$Status (.getStatus result)
       (get engine-status)))

(def ^ByteBuffer empty-buffer (ByteBuffer/allocateDirect (* 16 1024)))

(defn handshake!
  ([^SSLEngine engine x]
   (handshake! engine x (.getHandshakeStatus engine)))
  ([^SSLEngine engine x ^SSLEngineResult$HandshakeStatus handshake-status]
   (let [{{:keys [reserve commit]} :nio/out
          {:keys [block decommit]} :nio/in} x
         hs (handshake? engine)
         ;;_ (prn ::hs hs)
         step (condp = hs
                :finished
                (do
                  :finished)

                :need-task
                (do
                  (prn ::executing ::task)
                  (-> (.getDelegatedTask engine)
                      ^Runnable (.run))
                  (handshake? engine))

                ;; write data to network
                :need-wrap
                (let [^ByteBuffer dst (reserve)
                      ;;_ (prn ::wrap (handshake? engine) dst)
                      result (try
                               (-> engine
                                   (.wrap empty-buffer dst)
                                   (result?))
                               (catch SSLException e
                                 (prn ::wrap e)
                                 :closed))]
                  (condp = result
                    :buffer-overflow
                    :buffer-overflow
                    :buffer-underflow
                    :buffer-underflow
                    :closed
                    :closed
                    :ok
                    (do
                      (.flip dst)
                      (commit dst)
                      #_(.interestOps sk SelectionKey/OP_WRITE)
                      (handshake? engine))))

                ;; read data from network
                :need-unwrap
                (let [^ByteBuffer bb (block)]
                  (if (.hasRemaining bb)
                    (let [result (try
                                   (-> engine
                                       (.unwrap bb empty-buffer)
                                       (result?))
                                   (catch SSLException e
                                     (prn ::unwrap e)
                                     :buffer-underflow))]
                      (condp = result
                        :buffer-overflow
                        :buffer-overflow
                        :buffer-underflow
                        :buffer-underflow
                        :closed
                        :closed
                        :ok
                        (do
                          (decommit bb)
                          #_(prn ::in bb)
                          #_(.interestOps sk SelectionKey/OP_READ)
                          (handshake? engine))))
                    :waiting-for-input))

                ;; read data to network
                ;; TODO: can we remove this case?
                :need-unwrap-again
                (do
                  (prn ::unwrap-again)
                  :tbd)
                :noop)]
     #_(prn ::step step)
     (let []
       (if-not (contains?  #{:need-task :need-wrap :need-unwrap} step)
         step
         (handshake! engine x (.getHandshakeStatus engine)))))))

#_(
   (in-ns 'jaq.http.xrf.ssl)
   *e
   )

(defn ^SSLContext context []
  (SSLContext/getDefault)
  #_(doto (SSLContext/getInstance "TLSv1.2")
      (.init nil nil nil)))

(defn ^SSLEngine ssl-engine [^SSLContext context]
  (.createSSLEngine context))

(defn ^SSLEngine client-mode [^SSLEngine engine]
  (doto engine (.setUseClientMode true)))

;; aka encode: plain src -> encoded dst
(defn wrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.wrap engine src dst)]))

;; aka decode: encoded src -> plain dst
(defn unwrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.unwrap engine src dst)]))

(defn configure [^SSLEngine engine ^String host]
  (let [params (.getSSLParameters engine)
        ^SNIServerName server-name (SNIHostName. host)]
    (.setServerNames params [server-name])
    (.setSSLParameters engine params)
    engine))

(def ssl-rf
  (fn [rf]
    (let [eng (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host]
               :ssl/keys [engine]
               {:keys [reserve commit block decommit]} :nio/out
               :as x}]
         (when-not @eng
           (let [engine (or engine
                            (-> (context) (ssl-engine) (client-mode) (configure host)))]
             (->> engine (vreset! eng)))
           (when-not engine
             (let [dst (reserve)]
               (.beginHandshake @eng)
               (prn ::handshake host dst )
               (-> @eng (.wrap empty-buffer dst) #_(result?))
               (.flip dst)
               (commit dst))))
         (->> (assoc x :ssl/engine ^SSLEngine @eng)
              (rf acc)))))))

#_(
   (in-ns 'jaq.http.xrf.ssl)

   (let [dst (ByteBuffer/allocate 24024)]
     (-> (context) (ssl-engine) (client-mode) (configure "jaq.alpeware.com")
         ;;(.getSession) #_(.getPacketBufferSize) (.getApplicationBufferSize)
         (doto (.beginHandshake))
         (.wrap empty-buffer dst)
         #_(result?))
     (.flip dst))

   )
(def handshake-rf
  (fn [rf]
    (let [status (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host]
               :nio/keys [attachment ^SelectionKey selection-key]
               :ssl/keys [engine]
               :as x}]
         (let [hs (-> engine (handshake?))]
           #_(prn ::handhsake hs ::x x)
           (if-not (contains? #{:finished :not-handshaking} hs)
             (do
               (handshake! engine x)
               acc)
             (do
               (when-not @status
                 (prn ::handshake hs)
                 (vreset! status hs))
               (rf acc x)))))))))

(defn request-ssl-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          request (volatile! nil)
          requests (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :ssl/keys [^SSLEngine engine]
               {:keys [reserve commit block decommit] :as bip} :nio/out
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
                     result (-> engine
                                (.wrap @request dst)
                                (result?))]
                 (condp = result
                   :closed
                   (throw (IllegalStateException. "Connection closed"))

                   ;; wait for socket out to clear
                   :buffer-overflow
                   (do
                     #_(prn result dst @request)
                     (rf acc))

                   :ok
                   (do
                     (.flip dst)
                     (commit dst)
                     (recur acc x))))
               (->> x
                    (rf acc))))))))))

#_(
   (in-ns 'jaq.http.xrf.ssl)
   *e
   (map (fn [e]
          (cond
            (string? e)
            (-> (.getBytes e)
                (ByteBuffer/wrap))

            (instance? ByteBuffer e)
            e)))
   )


(def response-ssl-rf
  (fn [rf]
    (let [done (volatile! false)
          done! (fn []
                  (vswap! done not))
          parsed (volatile! false)
          parsed! (fn []
                    (vswap! parsed not))
          response (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :ssl/keys [^SSLEngine engine]
               :nio/keys [^SelectionKey selection-key]
               {:keys [block decommit commit buf-b] :as bip-in} :nio/in
               {{:keys [reserve] :as bip-out} :context/bip} :nio/out
               :as x}]
         (if @done
           (->> (assoc x :context/done! done!)
                (rf acc))
           (let [;;_ (.interestOps selection-key SelectionKey/OP_READ)
                 ^ByteBuffer bb (block)
                 ;;_ (prn ::response bb)
                 ^ByteBuffer scratch (reserve)
                 result (if (.hasRemaining bb) #_(>= (.remaining bb) (-> engine (.getSession) (.getPacketBufferSize)))
                            (try
                              (-> ^SSLEngine engine
                                  (.unwrap bb scratch)
                                  (result?))
                              (catch SSLException e
                                (prn e)
                                :buffer-underflow))
                            :buffer-underflow)]
             #_(prn ::result result bb)
             (condp = result
               :closed
               (throw (IllegalStateException. "Connection closed"))

               :buffer-underflow
               (do
                 #_(prn ::buffer-underflow ::compacting bb buf-b scratch)
                 (if-not (and (.hasRemaining bb) (> (.limit buf-b) 0))
                   acc
                   ;; compact & merge region a and b of bip
                   (do
                     (prn ::buffer-underflow ::compacting bb buf-b scratch)
                     (.put scratch bb)
                     (decommit bb)
                     (let [^ByteBuffer bb2 (block)]
                       (.put scratch bb2)
                       (decommit bb2)
                       (.flip scratch)
                       (let [^ByteBuffer bb3 ((:reserve bip-in))]
                         (.put bb3 scratch)
                         (.flip bb3)
                         (commit bb3))))))

               :buffer-overflow
               (prn ::buffer-overflow bb scratch)
               acc

               :ok
               (do
                 #_(.interestOps selection-key SelectionKey/OP_READ)
                 ;; TODO: looks like decommitting a partially read buffer has a bug?
                 (decommit bb)
                 (.flip scratch)
                 (when (.hasRemaining scratch)
                   (->> scratch
                        (.limit)
                        (range)
                        (map (fn [_]
                               (let [b (-> scratch (.get))]
                                 (if @parsed
                                   (->> (assoc x
                                               :context/parsed! parsed!
                                               :context/done! done!
                                               :byte b)
                                        (rf acc))
                                   (->> (assoc x
                                               :context/parsed! parsed!
                                               :context/done! done!
                                               :char (char b))
                                        (rf acc)))
                                 #_(->> (assoc x :char (char b) :byte b) (rf acc))
                                 #_(->> c (assoc x :char) (rf acc)))))
                        (doall))
                   #_(prn ::response bb scratch (block) (.hasRemaining bb)))
                 (if-not (.hasRemaining bb)
                   acc
                   (do
                     #_(prn ::recur bb)
                     (recur acc x))))))))))))

(defn receive-ssl-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          result (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :ssl/keys [^SSLEngine engine]
               :nio/keys [^SelectionKey selection-key]
               {:keys [block decommit commit buf-b] :as bip-in} :nio/in
               {:keys [reserve] :as bip-out} :nio/out
               :as x}]
         (if @once
           (->> x
                (rf acc))
           (let [^ByteBuffer bb (block)
                 ^ByteBuffer scratch (reserve)
                 result (if (.hasRemaining bb)
                            (try
                              (-> ^SSLEngine engine
                                  (.unwrap bb scratch)
                                  (result?))
                              (catch SSLException e
                                (prn e)
                                :buffer-underflow))
                            :buffer-underflow)]
             (condp = result
               :closed
               (throw (IllegalStateException. "Connection closed"))

               :buffer-underflow
               (do
                 (if-not (and (.hasRemaining bb) (> (.limit buf-b) 0))
                   acc
                   ;; compact & merge region a and b of bip
                   (do
                     (prn ::buffer-underflow ::compacting bb buf-b scratch)
                     (.put scratch bb)
                     (decommit bb)
                     (let [^ByteBuffer bb2 (block)]
                       (.put scratch bb2)
                       (decommit bb2)
                       (.flip scratch)
                       (let [^ByteBuffer bb3 ((:reserve bip-in))]
                         (.put bb3 scratch)
                         (.flip bb3)
                         (commit bb3)))
                     acc)))

               :buffer-overflow
               (prn ::buffer-overflow bb scratch)
               acc

               :ok
               (do
                 (decommit bb)
                 (.flip scratch)
                 (when (.hasRemaining scratch)
                   (->> scratch
                        (.limit)
                        (range)
                        (map (fn [_]
                               (let [b (-> scratch (.get))]
                                 (xrf acc (assoc x :byte b)))))
                        (doall)))
                 (cond
                   (xrf)
                   (do
                     (vreset! once true)
                     (rf acc (xrf)))

                   (not (.hasRemaining bb))
                   acc

                   :else
                   (recur acc x)))))))))))

#_(
   *ns*
   (require 'jaq.http.xrf.ssl :reload)
   (in-ns 'jaq.http.xrf.ssl)
   *e

   (let [{:ssl/keys [engine]} {:ssl/engine :foo}]
     engine)
   )
