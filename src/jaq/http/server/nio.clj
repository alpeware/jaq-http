(ns jaq.http.server.nio
  (:gen-class)
  (:require
   [taoensso.tufte :as tufte :refer [defnp fnp]]
   [jaq.async.fj :as fj]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.io IOException]
   [java.net InetSocketAddress ServerSocket Socket]
   [java.nio.charset StandardCharsets Charset]
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [java.util Set]))

(set! *warn-on-reflection* true)

(def stats-accumulator (tufte/add-accumulating-handler! {:ns-pattern "*"}))

(def ^:dynamic *http-server* nil)

(def ^:dynamic *app-xrf* nil)

(def pending-connections (* 16 1024))
(def socket-buffer-size (* 16 1024))
(def buffer-size (* 32 1024))

(def ^Charset charset StandardCharsets/UTF_8)

#_(def ^ByteBuffer read-buffer (ByteBuffer/allocateDirect buffer-size))

(defn non-blocking [^AbstractSelectableChannel channel]
  (.configureBlocking channel false))

(defn ^ServerSocketChannel server-channel []
  (-> (ServerSocketChannel/open)
      (non-blocking)))

(defn ^ServerSocket socket [^ServerSocketChannel ssc]
  (doto (.socket ssc)
    (.setReuseAddress true)
    (.setReceiveBufferSize socket-buffer-size)))

(defn client-socket [^Socket socket]
  (doto socket
    (.setTcpNoDelay true)
    (.setReceiveBufferSize socket-buffer-size)
    (.setSendBufferSize socket-buffer-size)
    (.setReuseAddress true)))

(defn bind [^ServerSocket ss port backlog]
  (.bind ss (InetSocketAddress. port) backlog))

(defn ^Selector selector! [] (Selector/open))

(defn ^SelectionKey listener [^ServerSocketChannel ssc ^Selector selector]
  (.register ssc selector SelectionKey/OP_ACCEPT))

(defn select! [^Selector selector]
  (.select selector))

(defn ^SocketChannel client-channel [^ServerSocketChannel ssc]
  (some-> (.accept ssc)
          (non-blocking)))

(defn ^SelectionKey readable [^Selector selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_READ))

(defn ^SelectionKey connectable [^Selector selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_CONNECT))

(defn write-channel [^SocketChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn read-channel [^SocketChannel channel ^ByteBuffer buf]
  (.read channel buf))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   *e
   )

(defnp read! [^ByteBuffer read-buffer ^SelectionKey channel-key]
  (let [;;{:keys [state]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (let [n (->> read-buffer
                 (.clear)
                 (read-channel channel))]
      (.flip read-buffer)
      (cond
        (< n 0) ;; end of stream
        (do
          (.interestOps channel-key 0)
          (.cancel channel-key))

        (> n 0) ;; read some bytes
        (let [bb (->> read-buffer
                      ^CharBuffer (. charset decode)
                      (.asReadOnlyBuffer))]
          (.attach channel-key {:in bb :state :process})
          channel-key)))))

(defnp write! [^SelectionKey channel-key]
  (let [{:keys [^ByteBuffer out]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (when out #_(and out (.isValid channel-key) (.isOpen channel))
          (let [n (write-channel channel out)
                r (.remaining out)]
            (if (= r 0) ;; end of buf
              (do
                (.close channel)
                (.cancel channel-key))

              (do
                (.interestOps channel-key SelectionKey/OP_WRITE)
                (-> channel-key (.selector) (.wakeup))))))))

(defnp accept! [ssc ^Selector selector]
  (some->> ssc
           (client-channel)
           (readable selector)))

(defnp process! [selected-keys]
  (doseq [^SelectionKey sk selected-keys]
    (let [{:keys [^ByteBuffer in
                  ^ByteBuffer out
                  state xf]
           :as attachment
           ;;:or {xf (*app-xrf* (rf/result-fn))}
           } (.attachment sk)]
      #_(prn ::attachment attachment)
      (try
        (condp = state
          :process
          (do
            (let [xf (or xf (*app-xrf* (rf/result-fn)))]
              ;; TODO: split into sub-tasks based on size of input buf
              (tufte/p ::xf
                       (run! (fn [x] (xf nil x)) in))
              (if-let [buf (some-> (xf))]
                (do ;; enough input to produce a response
                  (.attach sk {:state :processed :out buf})
                  (.interestOps sk SelectionKey/OP_WRITE)
                  #_(-> sk (.selector) (.wakeup)))
                (do ;; need more input so store current xf state
                  (.attach sk {:state :reading :xf xf})))))

          :processed
          (write! sk)
          :noop)
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

(defnp keys! [^ServerSocketChannel ssc
              all-selectors
              ^ByteBuffer read-buffer
              selected-keys
              ^SelectionKey sk]
  (or
   (some->>
    ;; TODO: use ready set directly
    (try
      (cond
        #_(not (.isValid sk))
        #_(.cancel sk)

        (.isAcceptable sk)
        (accept! ssc (rand-nth all-selectors))

        (.isReadable sk)
        (read! read-buffer sk)

        (.isWritable sk)
        sk)
      (catch CancelledKeyException _
        nil))
    (conj selected-keys))
   selected-keys))

;; TODO: fork multiple selectors
;; TODO: extract reducing fn
(defnp reactor-main [^ServerSocketChannel ssc
                     ^ByteBuffer read-buffer
                     ^Selector selector
                     all-selectors]
  (when (> (select! selector) 0)
    (let [^Set keys-set (.selectedKeys selector)
          ready-set (into #{} keys-set)
          _ (.clear keys-set)]
      (->> ready-set (reduce (partial keys! ssc all-selectors read-buffer) [])))))

(defnp reactor-clients [^ByteBuffer read-buffer ^Selector selector]
  (when (> (select! selector) 0)
    (let [^Set keys-set (.selectedKeys selector)
          ready-set (into #{} keys-set)
          _ (.clear keys-set)]
      (->> ready-set
           (reduce (partial keys! _ _ read-buffer) [])))))


#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   *e
   (zero? (bit-and 4 SelectionKey/OP_READ))

   (defonce stats-acc
     (tufte/add-accumulating-handler! {:ns-pattern "*"}))
   (tufte/profile
    {:id :test}
    *ns*)
   (def s (->> @stats-acc :selector (deref)))
   (->> @stats-acc
        :main
        (tufte/format-grouped-pstats))

   (alter-var-root
    #'*app-xrf* (constantly app/repl))
   )

(defnp wakeup! [selection-keys]
  (->> selection-keys
       (map (fn [^SelectionKey sk]
              (.selector sk)))
       (set)
       (map (fnp [^Selector e] (.wakeup e)))))

(defn serve [xrf port]
  (let [selectors 0
        ssc (server-channel)
        socket (socket ssc)
        main-selector (selector!)
        ;; TODO: dynamically add and remove additional selectors
        client-selectors (->> (range selectors) (map (fn [_] (selector!))) (doall))
        all-selectors (conj client-selectors main-selector)
        listener-keys (listener ssc main-selector)
        shutdown (volatile! false)]
    ;; app
    (alter-var-root
     #'*app-xrf* (constantly xrf))
    ;; bind
    (bind socket port pending-connections)
    ;; reactor pattern
    ;; see http://gee.cs.oswego.edu/dl/cpjslides/nio.pdf
    (alter-var-root
     #'*http-server*
     (constantly
      {:xrf xrf
       :ssc ssc
       :socket socket
       :main-selector main-selector
       :shutdown-fn (fn []
                      (vreset! shutdown true)
                      (->> all-selectors
                           (map (fn [^Selector e] (.wakeup e)))
                           (dorun)))
       :main (fj/thread
               (let [read-buffer (ByteBuffer/allocateDirect buffer-size)
                     client-selectors (if (seq client-selectors)
                                        client-selectors
                                        [main-selector])
                     event-fn (if (> selectors 0)
                                (comp
                                 identity)
                                (comp
                                 process-keys!))]
                 (prn ::server ::listening port)
                 (loop []
                   (when-not @shutdown
                     (tufte/profile
                      {:id :main}
                      (some->>
                       (reactor-main ssc read-buffer main-selector client-selectors)
                       (event-fn)
                       (wakeup!)
                       (dorun)))
                     (recur)))
                 (try
                   (prn ::accept ::shutdown)
                   (.close main-selector)
                   (.close ssc)
                   (.close socket)
                   (catch IOException e
                     (prn ::shutdown e)))
                 (prn "---- stats ----")
                 (println (tufte/format-grouped-pstats @stats-accumulator))))
       :threads (->> client-selectors
                     (map-indexed (fn [i ^Selector selector]
                                    (fj/thread
                                      (let [read-buffer (ByteBuffer/allocateDirect buffer-size)]
                                        (prn ::client ::selector)
                                        (loop []
                                          (when-not @shutdown
                                            (tufte/profile
                                             {:id (keyword "client" (str i))}
                                             (some->> (reactor-clients read-buffer selector)
                                                      (process-keys!)
                                                      (wakeup!)
                                                      (dorun)))
                                            (recur)))
                                        (try
                                          (prn ::accept ::shutdown)
                                          (.close selector)
                                          (catch IOException e
                                            (prn ::shutdown e)))))))
                     (doall))}))))

#_(
   *ns*
   *e
   (require 'jaq.http.server.nio :reload)
   (in-ns 'jaq.http.server.nio)
   *http-server*
   *e

   (-> *http-server* :shutdown-fn (apply []))

   (-> *http-server* :threads (first) (.isInterrupted))
   (-> *http-server* :threads (first) (.interrupt))

   (slurp "http://localhost:10010/")

   (slurp (java.io.FileReader. "/proc/sys/net/core/rmem_max"))

   (require 'clojure.repl)
   (clojure.repl/doc alter-var-root)

   )

(defn -main [& args]
  (serve app/repl 3000))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   (println (tufte/format-grouped-pstats @stats-accumulator))
   )
