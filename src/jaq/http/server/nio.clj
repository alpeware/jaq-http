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
   [java.net InetSocketAddress ServerSocket]
   [java.nio.charset StandardCharsets Charset]
   [java.nio.channels ServerSocketChannel Selector SelectionKey SocketChannel]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [java.util UUID Locale]
   [java.util.concurrent ArrayBlockingQueue ThreadPoolExecutor TimeUnit]))

(def ^:dynamic *http-server* nil)

(def ^:dynamic *app-xrf* nil)

(def ^:dynamic *chan-buf* 1)

(def buffer-size (* 256 1024))

(def charset StandardCharsets/UTF_8)

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

(defn socket [ssc]
  (.socket ssc))

(defn bind [socket port backlog]
  (.bind socket (InetSocketAddress. port) backlog))

(defn selector [] (Selector/open))

(defn listener [ssc selector]
  (.register ssc selector SelectionKey/OP_ACCEPT))

(defn select [selector]
  (.selectNow selector))

(defn ^SocketChannel client-channel [^ServerSocketChannel ssc]
  (-> (.accept ssc)
      (non-blocking)))

(defn readable [selector ^SocketChannel channel]
  (.register channel selector SelectionKey/OP_READ))

(defn response [{:keys [status headers body]}]
  (->> ["HTTP/1.1" " " status " " "OK" "\r\n"
        ;;"Host: " (:host headers) "\r\n"
        ;;"Date: Sat, 02 Nov 2019 21:16:00 GMT" "\r\n"
        "Content-type: text/plain" "\r\n"
        "Connection: close" "\r\n"
        "Content-length: " (count body) "\r\n"
        "\r\n"
        body]
       (apply str)))

(defn write-channel [^SocketChannel channel bytes]
  (.write channel bytes))

(defn connection [^SelectionKey channel-key]
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
                     (.getBytes charset)
                     (ByteBuffer/wrap))]
        (async/close! req)
        (async/close! ch)
        (->> {:buf buf}
             (.attach channel-key))
        (.interestOps channel-key SelectionKey/OP_WRITE)))

    (->> {:req req}
         (.attach channel-key))))

(defn close [ch]
  (when ch
    (async/close! ch)))

(defn handle-read [^SelectionKey channel-key]
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
              (close req))

            (> n 0) ;; read some bytes
            (->> read-buffer
                 (. charset decode)
                 (.asReadOnlyBuffer)
                 (async/>!! req))))
        (catch IOException e
          (close req)
          (prn ::client ::socket ::io e))
        (catch IllegalStateException e
          (close req)
          (prn ::client ::socket ::wrong ::state e))))))

(defn handle-write [^SelectionKey channel-key]
  (let [{:keys [buf]} (.attachment channel-key)
        ^SocketChannel channel (.channel channel-key)]
    (try
      (let [n (.write channel buf)
            r (.remaining buf)]
        (if (= r 0) ;; end of buf
          (do
            (.close channel)
            (.cancel channel-key))

          (.interestOps channel-key SelectionKey/OP_WRITE)))
      (catch IOException e
        (prn ::client ::socket ::io e))
      (catch IllegalStateException e
        (prn ::client ::socket ::wrong ::state e)))))

(defn accept [ssc client-selector]
  (->> (client-channel ssc)
       (readable client-selector)
       (connection)))

(defn serve [xrf port]
  (let [ssc (server-channel)
        socket (socket ssc)
        accept-selector (selector)
        client-selector (selector)
        listener-keys (listener ssc accept-selector)
        shutdown (async/chan)
        shutdown-mult (async/mult shutdown)
        accept-shutdown (async/chan)
        requests-shutdown (async/chan)
        responses-shutdown (async/chan)]
    ;; app
    (alter-var-root #'*app-xrf* (constantly xrf))
    ;; shutdown hooks
    (async/tap shutdown-mult accept-shutdown)
    (async/tap shutdown-mult requests-shutdown)
    (async/tap shutdown-mult responses-shutdown)
    ;; bind
    (bind socket port 0)
    ;; accept
    (async/go-loop []
      (let [[_ ch] (async/alts! [accept-shutdown (async/timeout 1)])]
        (if (= ch accept-shutdown)
          (try
            ;; TODO: doesn't free the port
            (prn ::accept ::shutdown)
            (.close ssc)
            (.close socket)
            (.wakeup accept-selector)
            (catch IOException _))
          (let [ready (select accept-selector)]
            (when (> ready 0)
              (let [it (-> accept-selector (.selectedKeys) (.iterator))]
                (loop []
                  (when (.hasNext it)
                    (let [^SelectionKey channel-key (.next it)]
                      (.remove it)
                      (when (.isAcceptable channel-key)
                        (accept ssc client-selector)))
                    (recur)))))
            (recur)))))
    ;; handle requests
    (async/go-loop []
      (let [[_ ch] (async/alts! [requests-shutdown (async/timeout 1)])]
        (if (= ch requests-shutdown)
          (do
            ;; TODO: close all client sockets?
            (.wakeup client-selector)
            (prn ::requests ::shutdown))
          (let [ready (select client-selector)]
            (when (> ready 0)
              (let [it (-> client-selector (.selectedKeys) (.iterator))]
                (loop []
                  (when (.hasNext it)
                    (try
                      (let [^SelectionKey channel-key (.next it)]
                        (.remove it)
                        (when (.isReadable channel-key)
                          (handle-read channel-key))
                        (when (.isWritable channel-key)
                          (handle-write channel-key)))
                      (catch Exception e
                        (prn ::requests e)))
                    (recur)))))
            (recur)))))
    (prn ::server ::listening port)
    (alter-var-root
     #'*http-server*
     (constantly {:xrf xrf
                  :ssc ssc
                  :socket socket
                  :accept-selector accept-selector
                  :client-selector client-selector
                  :shutdown shutdown}))))

#_(
   *ns*
   (require 'jaq.http.server.nio :reload)
   (in-ns 'jaq.http.server.nio)

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
