(ns jaq.http.server.nio
  (:gen-class)
  (:require
   [taoensso.tufte :as tufte]
   [jaq.async.fj :as fj]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.io IOException]
   [java.net InetSocketAddress ServerSocket Socket]
   [java.nio.charset StandardCharsets Charset]
   [java.nio.channels
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio ByteBuffer CharBuffer]))

(set! *warn-on-reflection* true)

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

(defn ^Selector selector [] (Selector/open))

(defn ^SelectionKey listener [^ServerSocketChannel ssc ^Selector selector]
  (.register ssc selector SelectionKey/OP_ACCEPT))

(defn select [^Selector selector]
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

;; TODO: remove?
;; TODO: investigate wait for state connected?
(defn ^SelectionKey exchange [^SelectionKey channel-key]
  (let [^SocketChannel channel (.channel channel-key)]
    (->> {:state :connected}
         (.attach channel-key))
    channel-key))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   *e
   )

(defn read! [^ByteBuffer read-buffer ^SelectionKey channel-key]
  (let [;;{:keys [state]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (try
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
            channel-key
            ;; inline read
            #_(let [{:keys [^ByteBuffer in xf]
                     :or {xf (*app-xrf* (rf/result-fn))}} (.attachment channel-key)]
                (run! (fn [x] (xf nil x)) in)
                (if-let [buf (some-> (xf))]
                  (do ;; enough input to produce a response
                    (.attach channel-key {:state :processed :out buf})
                    (.interestOps channel-key SelectionKey/OP_WRITE)
                    (-> channel-key (.selector) (.wakeup)))
                  (do ;; need more input so store current xf state
                    (.attach channel-key {:state :reading :xf xf}))))

            ;; fork each read
            #_(tufte/p
               ::fork
               (reader-task channel-key))

            #_(->> {:state :read}
                   (.attach channel-key)))))
      (catch IOException e
        (prn ::client ::socket ::io e))
      (catch IllegalStateException e
        (prn ::client ::socket ::wrong ::state e)))))

(defn write! [^SelectionKey channel-key]
  (let [{:keys [^ByteBuffer out]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (when out #_(and out (.isValid channel-key) (.isOpen channel))
      (try
        (let [n (write-channel channel out)
              r (.remaining out)]
          (if (= r 0) ;; end of buf
            (do
              (.close channel)
              (.cancel channel-key))

            (do
              (.interestOps channel-key SelectionKey/OP_WRITE)
              (-> channel-key (.selector) (.wakeup)))))
        (catch IOException e
          (.cancel channel-key)
          #_(prn ::client ::socket ::io e))
        (catch IllegalStateException e
          (prn ::client ::socket ::wrong ::state e))))))

(defn accept! [ssc ^Selector client-selector]
  (some->> ssc
           (client-channel)
           (readable client-selector)
           #_(connectable client-selector)
           #_(exchange))
  (.wakeup client-selector))

(defn reader-task [^SelectionKey channel-key]
  (->
   (fn []
     (let [{:keys [^ByteBuffer in xf]
            :or {xf (*app-xrf* (rf/result-fn))}} (.attachment channel-key)]
       ;; TODO: split into sub-tasks based input buf
       (run! (fn [x] (xf nil x)) in)
       (if-let [buf (some-> (xf))]
         (do ;; enough input to produce a response
           (.attach channel-key {:state :processed :out buf})
           (.interestOps channel-key SelectionKey/OP_WRITE)
           (-> channel-key (.selector) (.wakeup)))
         (do ;; need more input so store current xf state
           (.attach channel-key {:state :reading :xf xf})))))
   (fj/task)
   (fj/fork)))

(defn process [channel-keys]
  (doseq [^SelectionKey channel-key channel-keys]
    (let [{:keys [^ByteBuffer in
                  ^ByteBuffer out
                  state xf]
           :or {xf (*app-xrf* (rf/result-fn))}} (.attachment channel-key)]
      (condp = state
        :process
        (do
          ;; TODO: split into sub-tasks based input buf
          (run! (fn [x] (xf nil x)) in)
          (if-let [buf (some-> (xf))]
            (do ;; enough input to produce a response
              (.attach channel-key {:state :processed :out buf})
              (.interestOps channel-key SelectionKey/OP_WRITE)
              (-> channel-key (.selector) (.wakeup)))
            (do ;; need more input so store current xf state
              (.attach channel-key {:state :reading :xf xf}))))

        :processed
        (write! channel-key)
        :noop))))

(defn process-reads [channel-keys]
  ;; TODO: Dynamically determine batch size
  (if (> (count channel-keys) 10)
    ;; fork
    (->> channel-keys
         (partition 20)
         (map (fn [block]
                (-> (fn [] (process block))
                    #_(fj/invoke)
                    (fj/task)
                    (fj/fork))))
         (dorun))
    ;; just do the work
    (process channel-keys)))

;; TODO: fork multiple selectors
(defn reactor-main [^ServerSocketChannel ssc
                    ^ByteBuffer read-buffer
                    ^Selector main-selector
                    all-selectors]
  (tufte/p
   ::selector
   (let [ready (select main-selector)]
     (when (> ready 0)
       (let [it (-> main-selector (.selectedKeys) (.iterator))]
         (loop [channel-keys []]
           (let [^SelectionKey channel-key (.next it)
                 read-key (cond
                            (not (.isValid channel-key))
                            (.cancel channel-key)

                            (.isAcceptable channel-key)
                            ;; randomly assign a selector
                            (do
                              (accept! ssc (rand-nth all-selectors))
                              nil)

                            (.isConnectable channel-key)
                            (.interestOps channel-key SelectionKey/OP_READ)

                            (.isReadable channel-key)
                            (read! read-buffer channel-key)

                            (.isWritable channel-key)
                            channel-key)
                 channel-keys (if read-key
                                (conj channel-keys read-key)
                                channel-keys)]
             (.remove it)
             (if-not (.hasNext it)
               channel-keys
               (recur channel-keys)))))))))

(defn reactor-clients [^ByteBuffer read-buffer ^Selector client-selector]
  (tufte/p
   ::clients
   (let [ready (select client-selector)]
     (when (> ready 0)
       (let [it (-> client-selector (.selectedKeys) (.iterator))]
         (loop [channel-keys []]
           (let [^SelectionKey channel-key (.next it)
                 read-key (try
                            (cond
                              (not (.isValid channel-key))
                              (.cancel channel-key)

                              ;; doesn't seem to add anything
                              (.isConnectable channel-key)
                              (.interestOps channel-key SelectionKey/OP_READ)

                              (.isReadable channel-key)
                              (read! read-buffer channel-key)

                              (.isWritable channel-key)
                              channel-key)
                            (catch CancelledKeyException _
                              nil))
                 channel-keys (if read-key
                                (conj channel-keys read-key)
                                channel-keys)]
             (.remove it)
             (if-not (.hasNext it)
               channel-keys
               (recur channel-keys)))))))))

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
   )

(defn serve [xrf port]
  (let [ssc (server-channel)
        socket (socket ssc)
        main-selector (selector)
        ;; TODO: dynamically add and remove additional selectors
        client-selectors (->> (range 3) (map (fn [_] (selector))) (doall))
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
               (let [read-buffer (ByteBuffer/allocateDirect buffer-size)]
                 (prn ::server ::listening port)
                 (loop []
                   (when-not @shutdown
                     (-> (reactor-main ssc read-buffer main-selector all-selectors)
                         (process-reads))
                     (->> client-selectors
                          (map (fn [^Selector e] (.wakeup e)))
                          (dorun))
                     (recur)))
                 (try
                   ;; TODO: doesn't free the port?
                   (prn ::accept ::shutdown)
                   (.close main-selector)
                   (.close ssc)
                   (.close socket)
                   (catch IOException e
                     (prn ::shutdown e)))))
       :threads (->> client-selectors
                     (map (fn [^Selector client-selector]
                            (fj/thread
                              (let [read-buffer (ByteBuffer/allocateDirect buffer-size)]
                                (prn ::client ::selector)
                                (loop []
                                  (when-not @shutdown
                                    (-> (reactor-clients read-buffer client-selector)
                                        (process-reads))
                                    (recur)))
                                (try
                                  ;; TODO: doesn't free the port?
                                  (prn ::accept ::shutdown)
                                  (.close client-selector)
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

   (slurp "http://localhost:10010/")

   (slurp (java.io.FileReader. "/proc/sys/net/core/rmem_max"))

   (require 'clojure.repl)
   (clojure.repl/doc alter-var-root)

   )

(defn -main [& args]
  (->> (serve app/main 3000)
       :future
       (deref)))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   )
