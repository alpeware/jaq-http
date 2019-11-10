(ns jaq.http.server.nio
  (:gen-class)
  (:require
   [clojure.core.async :as async]
   [clojure.edn :as edn]
   [clojure.walk :as walk]
   [jaq.http.xrf.app :as app])
  (:import
   [java.io IOException]
   [java.net URLDecoder URI]
   [java.net InetSocketAddress ServerSocket Socket]
   [java.nio.charset StandardCharsets Charset]
   [java.nio.channels
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [java.util UUID Locale]
   [java.util.concurrent ArrayBlockingQueue ThreadPoolExecutor TimeUnit]))

(set! *warn-on-reflection* true)

(def ^:dynamic *http-server* nil)

(def ^:dynamic *app-xrf* nil)

(def ^:dynamic *chan-buf* 1)

(def pending-connections (* 16 1024))
(def socket-buffer-size (* 16 1024))
(def buffer-size (* 32 1024))

(def ^Charset charset StandardCharsets/UTF_8)

(def ^ByteBuffer read-buffer (ByteBuffer/allocateDirect buffer-size))

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(defn uuid []
  (->
   (UUID/randomUUID)
   (str)
   (keyword)))

(defn non-blocking [^AbstractSelectableChannel channel]
  (.configureBlocking channel false))

(defn ^ServerSocketChannel server-channel []
  (-> (ServerSocketChannel/open)
      (non-blocking)))

(defn ^ServerSocket socket [^ServerSocketChannel ssc]
  (doto (.socket ssc)
    (.setReuseAddress true)
    (.setReceiveBufferSize socket-buffer-size)))

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

(defn ^String response [{:keys [status headers body]}]
  (->> ["HTTP/1.1" " " status " " "OK" "\r\n"
        ;;"Host: " (:host headers) "\r\n"
        ;;"Date: Sat, 02 Nov 2019 21:16:00 GMT" "\r\n"
        "Content-type: text/plain" "\r\n"
        "Connection: close" "\r\n"
        "Content-length: " (count body) "\r\n"
        "\r\n"
        body]
       (apply str)))

(defn write-channel [^SocketChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn close! [ch]
  (when ch
    (async/close! ch)))

(defn ^SelectionKey exchange [^SelectionKey channel-key]
  (let [^SocketChannel channel (.channel channel-key)
        req (async/chan *chan-buf*)
        ch (async/chan *chan-buf* *app-xrf* (fn [e] (prn ::exception e) {:exception e}))]

    ;; req
    (async/go-loop []
      (when-let [buf (async/<! req)]
        (async/onto-chan ch buf false)
        (recur)))

    ;; res
    (async/go
      (let [res (async/<! ch)
            buf (-> res
                    (response)
                    ^String (.getBytes charset)
                    (ByteBuffer/wrap))]
        (close! req)
        (close! ch)
        (->> {:buf buf}
             (.attach channel-key))
        (.interestOps channel-key SelectionKey/OP_WRITE)
        (-> channel-key (.selector) (.wakeup))))

    (->> {:req req}
         (.attach channel-key))

    channel-key))


(defn read! [^SelectionKey channel-key]
  (let [{:keys [req]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (when req
      (try
        (let [n (->> read-buffer
                     (.clear)
                     (.read channel))]
          (.flip read-buffer)
          (cond
            (< n 0) ;; end of stream
            (do
              (.interestOps channel-key 0)
              (close! req))

            (> n 0) ;; read some bytes
            (->> read-buffer
                 ^CharBuffer (. charset decode)
                 (.asReadOnlyBuffer)
                 (async/>!! req))))
        (catch IOException e
          (close! req)
          (prn ::client ::socket ::io e))
        (catch IllegalStateException e
          (close! req)
          (prn ::client ::socket ::wrong ::state e))))))

(defn write! [^SelectionKey channel-key]
  (let [{:keys [^ByteBuffer buf]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (try
      (let [n (.write channel buf)
            r (.remaining buf)]
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
        (prn ::client ::socket ::wrong ::state e)))))

(defn client-socket [^Socket socket]
  (doto socket
    (.setTcpNoDelay true)
    (.setReceiveBufferSize socket-buffer-size)
    (.setSendBufferSize socket-buffer-size)
    (.setReuseAddress true)))

(defn accept! [ssc client-selector]
  (some->> ssc
           (client-channel)
           (readable client-selector)
           (exchange)))

(defn serve [xrf port]
  (let [ssc (server-channel)
        socket (socket ssc)
        main-selector (selector)
        listener-keys (listener ssc main-selector)
        shutdown (async/chan)
        shutdown-mult (async/mult shutdown)
        main-shutdown (async/chan)]
    ;; app
    (alter-var-root
     #'*app-xrf* (constantly xrf))
    ;; shutdown hooks
    (async/tap shutdown-mult main-shutdown)
    ;; bind
    (bind socket port pending-connections)
    ;; reactor pattern
    ;; see http://gee.cs.oswego.edu/dl/cpjslides/nio.pdf
    (async/thread
      (loop []
        (if (async/poll! main-shutdown)
          (try
            ;; TODO: doesn't free the port
            (prn ::accept ::shutdown)
            (.close main-selector)
            (.close ssc)
            (.close socket)
            (catch IOException _))
          (let [ready (select main-selector)]
            (when (> ready 0)
              (let [it (-> main-selector (.selectedKeys) (.iterator))]
                (loop []
                  (when (.hasNext it)
                    (let [^SelectionKey channel-key (.next it)]
                      (.remove it)
                      (cond
                        (not (.isValid channel-key))
                        (.cancel channel-key)

                        (.isAcceptable channel-key)
                        (accept! ssc main-selector)

                        (.isReadable channel-key)
                        (read! channel-key)

                        (.isWritable channel-key)
                        (write! channel-key)))
                    (recur)))))
            (recur)))))
    (prn ::server ::listening port)
    (alter-var-root
     #'*http-server*
     (constantly
      {:xrf xrf
       :ssc ssc
       :socket socket
       :main-selector main-selector
       :shutdown shutdown}))))

#_(
   *ns*
   (require 'jaq.http.server.nio :reload)
   (in-ns 'jaq.http.server.nio)

   (set! *compile-path* "foo")
   *e

   (def http-server
     (serve 10010))
   (.close (::ssc http-server))

   (slurp "http://localhost:10010/")
   (async/>!! (::shutdown http-server) :shutdown)

   *e
   s
   (slurp (java.io.FileReader. "/proc/sys/net/core/rmem_max"))

   (require 'clojure.repl)
   (clojure.repl/doc alter-var-root)

   (alter-var-root #'*http-server* (constantly :foo))

   )

(defn -main [& args]
  (->> (or
        (some-> env :PORT (edn/read-string))
        3000)
       (serve app/main)
       :shutdown
       (async/<!!)))

#_(
   *ns*
   (in-ns 'jaq.http.server.nio)
   )
