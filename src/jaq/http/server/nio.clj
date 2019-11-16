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

(def ^ByteBuffer read-buffer (ByteBuffer/allocateDirect buffer-size))

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

(defn read! [^SelectionKey channel-key]
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
    (when out
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
          (prn ::client ::socket ::io e))
        (catch IllegalStateException e
          (prn ::client ::socket ::wrong ::state e))))))

(defn accept! [ssc client-selector]
  (some->> ssc
           (client-channel)
           (readable client-selector)
           #_(exchange)))

(defn reader-task [^SelectionKey channel-key]
  (->
   (fn []
     (let [{:keys [^ByteBuffer in xf]
            :or {xf (*app-xrf* (rf/result-fn))}} (.attachment channel-key)]
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
  (if (> (count channel-keys) 15)
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
(defn reactor-loop [^ServerSocketChannel ssc ^Selector main-selector]
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
                            (accept! ssc main-selector)

                            (.isReadable channel-key)
                            (read! channel-key)

                            (.isWritable channel-key)
                            channel-key)
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
       :shutdown-fn (fn [] (vreset! shutdown true) (.wakeup main-selector))
       :future (future
                 (do
                   (try
                     (do
                       (prn ::server ::listening port)
                       (loop []
                         (when-not @shutdown
                           (-> (reactor-loop ssc main-selector)
                               (process-reads))
                           (recur)))
                       (try
                         ;; TODO: doesn't free the port?
                         (prn ::accept ::shutdown)
                         (.close main-selector)
                         (.close ssc)
                         (.close socket)
                         (catch IOException e
                           (prn ::shutdown e))))
                     (catch Exception e
                       (prn ::event ::loop e)))
                   (prn ::done)))}))))

#_(
   *ns*
   (require 'jaq.http.server.nio :reload)
   (in-ns 'jaq.http.server.nio)
   *http-server*
   *e

   (def http-server
     (serve 10010))
   (.close (::ssc http-server))

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
