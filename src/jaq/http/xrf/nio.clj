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
   [java.io IOException]
   [java.nio.channels.spi AbstractSelectableChannel]
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel
    DatagramChannel ByteChannel]
   [java.nio.charset Charset]
   [java.nio ByteBuffer ByteOrder CharBuffer]
   [java.net InetSocketAddress ServerSocket Socket SocketAddress
    InetSocketAddress DatagramPacket]
   [javax.net.ssl
    SNIHostName SNIServerName
    SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status
    SSLContext SSLSession]
   [java.util.concurrent ConcurrentLinkedDeque]
   [java.util Set]))

#_(
   (in-ns 'jaq.http.xrf.nio)
   )

(def read-op SelectionKey/OP_READ)
(def write-op SelectionKey/OP_WRITE)

(defn address
  ([^Integer port]
   (InetSocketAddress. port))
  ([^String host ^Integer port]
   (InetSocketAddress. host port)))

(defn non-blocking [^AbstractSelectableChannel channel]
  (.configureBlocking channel false))

(defn ^SocketChannel channel! [^SocketAddress socket-address]
  (SocketChannel/open socket-address))

(defn ^SocketChannel datagram-channel! []
  (DatagramChannel/open))

(defn ^ServerSocketChannel server-channel! []
  (ServerSocketChannel/open))

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

(defn select!
  ([^Selector selector]
   (.select selector))
  ([^Selector selector ^long timeout]
   (.select selector timeout)))

(defn register! [^Selector selector attachment ^SelectableChannel channel]
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

(defn datagram-register! [^Selector selector attachment ^SelectableChannel channel]
  (.register channel
             selector
             SelectionKey/OP_READ
             attachment))

(defn datagram-connect! [^SocketAddress address ^DatagramChannel channel]
  (.connect channel address))

(defn datagram-bind! [address ^DatagramChannel channel]
  (.bind channel address))

(defn write-channel [^ByteChannel channel ^ByteBuffer bytes]
  (.write channel bytes))

(defn read-channel [^ByteChannel channel ^ByteBuffer buf]
  (.read channel buf))

(defn read! [{{:keys [reserve commit block decommit]} :nio/in
              :nio/keys [^SelectionKey selection-key]
              :as x}]
  (let [^ByteChannel channel (.channel selection-key)]
    (let [bb (reserve)
          n (try
              (->> bb (read-channel channel))
              (catch IOException ex
                (prn ::read ::ioexception ex)
                -1))]
      (cond
        (< n 0) ;; end of stream
        (do
          (prn ::eos selection-key)
          (.interestOps selection-key 0)
          (.cancel selection-key))

        (> n 0) ;; read some bytes
        (do
          #_(prn ::read n)
          (->> bb
               (.flip)
               (commit))))
      n)))

(defn receive-datagram-channel [^DatagramChannel channel ^ByteBuffer buf]
  (.receive channel buf))

(defn datagram-receive! [{{:keys [reserve commit block decommit]} :nio/in
                          :nio/keys [^SelectionKey selection-key]
                          :as x}]
  (let [^DatagramChannel channel (.channel selection-key)]
    (let [bb (reserve)
          socket-address (->> bb
                              (receive-datagram-channel channel))]
      (cond
        (nil? socket-address) ;; end of stream?
        (do
          (prn ::eos selection-key)
          #_(.interestOps selection-key 0)
          #_(.cancel selection-key))

        socket-address ;; read some bytes
        (do
          (prn ::received ::from socket-address)
          (->> bb
               (.flip)
               (commit))))
      socket-address)))

(defn send-datagram-channel [^DatagramChannel channel ^SocketAddress target ^ByteBuffer bytes]
  (.send channel bytes target))

(defn datagram-send! [{{:keys [reserve commit block decommit]} :nio/out
                       :nio/keys [^SelectionKey selection-key]
                       :http/keys [host port]
                       :as x}]
  (let [^DatagramChannel channel (.channel selection-key)]
    (let [bb (block)]
      (when (and (.hasRemaining bb) host port)
        (let [target (address host port)]
          (send-datagram-channel channel target bb)
          (prn ::wrote (.position bb) ::to target)
          (decommit bb)))
      (.position bb))))

#_(
   (in-ns 'jaq.http.xrf.nio)
   *e
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (read!))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x :nio/selection-key)
   )

(defn write! [{{:keys [reserve commit block decommit]} :nio/out
               :nio/keys [^SelectionKey selection-key]
               :as x}]
  (let [^ByteChannel channel (.channel selection-key)]
    (let [bb (block)]
      (when (.hasRemaining bb)
        (try
          (write-channel channel bb)
          (decommit bb)
          (catch IOException ex
            (prn ::eos selection-key)
            (.interestOps selection-key 0)
            (.cancel selection-key)))
        #_(prn ::wrote (.position bb)))
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
                   #_(prn ::written written)
                   (if-not (> written 0)
                     (do
                       ;; socket buffer full so waiting to clear
                       (writable! selection-key)
                       acc)
                     (do
                       (recur acc x)))))
               (if (empty? @requests)
                 (do
                   (vreset! once true)
                   (rf acc x))
                 acc)))))))))

(defn datagram-send-rf [xf]
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
                 (let [written (datagram-send! x)]
                   (prn ::written written)
                   (if-not (> written 0)
                     (do
                       ;; socket buffer full so waiting to clear
                       (writable! selection-key)
                       acc)
                     (do
                       (recur acc x)))))
               (if (empty? @requests)
                 (do
                   (vreset! once true)
                   (rf acc x))
                 acc)))))))))

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
                 (loop []
                   (->> (assoc x :byte (-> bb (.get) #_(bit-and 0xff)))
                        (xrf acc))
                   (when (and (.hasRemaining bb) (not (xrf)))
                     (recur)))
                 (prn bb)
                 (decommit bb)
                 (if-let [xr (xrf)]
                   (do
                     #_(prn ::receive ::result)
                     (vreset! once true)
                     (vreset! result xr)
                     (rf acc xr))
                   (recur acc x)))))
           (rf acc x)))))))

(defn datagram-receive-rf [xf]
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
                 (loop []
                   (->> (assoc x :byte (.get bb))
                        (xrf acc))
                   (when (and (.hasRemaining bb) (not (xrf)))
                     (recur)))
                 (prn bb)
                 (decommit bb)
                 (if-let [xr (xrf)]
                   (do
                     #_(prn ::receive ::result)
                     (vreset! once true)
                     (vreset! result xr)
                     (rf acc xr))
                   (recur acc x)))))
           (rf acc x)))))))

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

(def datagram-read-rf
  (fn [rf]
    (let [address (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
         (when (and (.isValid selection-key)
                    (.isReadable selection-key))
           (vreset! address (datagram-receive! x)))
         (->> (assoc x :nio/address @address)
              (rf acc)))))))

(def datagram-write-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:nio/keys [^SelectionKey selection-key] :as x}]
       (when (and (.isValid selection-key)
                  (.isWritable selection-key))
         (datagram-send! x))
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

(defn datagram-channel-rf [xf]
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
        ([acc {:http/keys [host port local-port local-host]
               :nio/keys [selector attachment]
               :as x}]
         (when-not @channel
           (->> (datagram-channel!)
                (non-blocking)
                (datagram-bind! (cond
                                  (and local-host local-port) (address local-host local-port)
                                  local-port (address local-port)
                                  :else nil))
                (vreset! channel)
                #_(datagram-connect! (address host port))
                (datagram-register! selector
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
                #_(writable!)
                (readable!)
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
#_(
   (in-ns 'jaq.http.xrf.nio)
   )

(defn datagram-bind-rf [xf]
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
        ([acc {:http/keys [host port local-port local-host]
               :nio/keys [selector attachment]
               :as x}]
         (when-not @channel
           (->> (datagram-channel!)
                (non-blocking)
                (datagram-bind! (address local-port))
                (vreset! channel)
                (datagram-connect! (address local-port))
                (datagram-register! selector
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
                (readable!)
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

#_(

   (let [host "239.255.255.250"
         port 1900
         selector (selector!)]
     (into []
           (comp
            selector-rf
            (datagram-channel-rf
             (comp
              read-rf
              write-rf)))
           [{:context/bip-size (* 1 4096)
             :http/host host
             :http/port port}]))

   *e

   )
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
        ([acc {:nio/keys [^Selector selector ^long timeout]
               :or {timeout 0}
               :as x}]
         (when-not @once
           (-> (xf (rf/result-fn))
               (apply [acc x]))
           (vreset! once true))
         (if (-> selector (.keys) (empty?))
           (rf acc x)
           (do
             (when (> (select! selector timeout) 0)
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
                                    :context/rf rf
                                    :context/x x
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
   #_(map (fn [{:http/keys [headers body] :as x}]
            (prn ::body body)
            (cond
              (ifn? body)
              (update x :http/body (body))

              :else
              x)))
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

#_(
   (in-ns 'jaq.http.xrf.nio)
   )

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

   (->> (java.net.NetworkInterface/getNetworkInterfaces)
        (enumeration-seq)
        (map (fn [e]
               (->> (.getInetAddresses e)
                    (enumeration-seq)
                    (map (fn [f] (.getHostAddress f)))))))

   ;; repl server
   (let [xf (comp
             selector-rf
             (map (fn [x]
                    (let [shutdown (volatile! nil)]
                      (assoc x
                             :context/shutdown shutdown
                             :context/shutdown! (fn []
                                                  (-> @shutdown (apply [])))))))
             (thread-rf
              (comp
               #_selector-rf
               (select-rf
                (comp
                 (bind-rf
                  (comp
                   #_(rf/once-rf (fn [{:context/keys [shutdown]
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
                     valid-rf
                     read-rf
                     write-rf
                     (rf/repeatedly-rf
                      (comp
                       (receive-rf
                        (comp
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
                          (fn [{:keys [path]}]
                            (str "/"
                                 (some-> path (string/split #"/") (second))))
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
                           "/ws" (comp
                                  (map (fn [{{:keys [sec-websocket-key]} :headers
                                             :as x}]
                                         #_(prn (:headers x))
                                         (assoc x
                                                :http/status 101
                                                :http/reason "Switching Protocols"
                                                :http/headers {:upgrade "websocket"
                                                               :connection "upgrade"
                                                               :sec-websocket-accept (jaq.http.xrf.websocket/handshake sec-websocket-key)}))))
                           "/out" (comp
                                   (map (fn [{:keys [path] :as x}]
                                          (assoc x :file/path (str "." path))))
                                   storage/file-rf
                                   storage/open-rf
                                   storage/read-rf
                                   storage/flip-rf
                                   storage/close-rf
                                   (rf/branch (fn [{:file/keys [size]}]
                                                (some-> size (> 0)))
                                              (map (fn [{:keys [path]
                                                         :file/keys [^ByteBuffer buf content-type]
                                                         :as x}]
                                                     (assoc x
                                                            :http/status 200
                                                            :http/reason "OK"
                                                            :http/headers {:content-type content-type
                                                                           :connection "keep-alive"}
                                                            :http/body buf)))
                                              (map (fn [{:keys [path]
                                                         :as x}]
                                                     (assoc x
                                                            :http/status 404
                                                            :http/reason "Not Found"
                                                            :http/headers {:content-type "text/plain"
                                                                           :connection "keep-alive"}
                                                            :http/body (str "Not found: " path))))))
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
                           :default (map (fn [{:keys [path]
                                               {:keys [host]} :headers
                                               :as x}]
                                           (assoc x
                                                  :http/status 404
                                                  :http/reason "Not Found"
                                                  :http/headers {:content-type "text/plain"
                                                                 :connection "keep-alive"}
                                                  :http/body (str "NOT FOUND " path " @ " host))))})))
                       writable-rf
                       (send-rf (comp
                                 response-rf))
                       readable-rf
                       ;; remember request
                       (rf/one-rf :http/request (map :http/request))
                       (map (fn [{:http/keys [request]
                                  {:keys [path]} :http/request
                                  :as x}]
                              (assoc x :path path)))
                       ;; sink for websocket
                       (rf/choose-rf :path {"/ws" (comp
                                                   (receive-rf
                                                    (comp
                                                     jaq.http.xrf.websocket/decode-frame-rf
                                                     jaq.http.xrf.websocket/decode-message-rf
                                                     #_(map (fn [x]
                                                              (assoc x
                                                                     :ws/message "hello"
                                                                     :ws/op :text)))
                                                     (rf/repeatedly-rf
                                                      (send-rf
                                                       (comp
                                                        jaq.http.xrf.websocket/encode-message-rf
                                                        jaq.http.xrf.websocket/encode-frame-rf)))
                                                     (fn [rf]
                                                       (let [once (volatile! false)]
                                                         (fn
                                                           ([] (rf))
                                                           ([acc] (rf acc))
                                                           ([acc {:nio/keys [selection-key]
                                                                  :context/keys [ws]
                                                                  :ws/keys [message op frames]
                                                                  :as x}]
                                                            #_(prn ::frame frame)
                                                            (prn ::message op)
                                                            (vswap! ws conj {:op op
                                                                             :frames frames})
                                                            #_(vswap! ws conj frame)
                                                            acc)))))))})))))))
                 (rf/once-rf (fn [{:context/keys [shutdown]
                                   :nio/keys [selector server-channel selection-key] :as x}]
                               (vreset! shutdown (fn []
                                                   (prn ::shutting ::down x)
                                                   (doseq [sk (.keys selector)]
                                                     (-> sk (.channel) (.close))
                                                     (-> sk (.cancel)))
                                                   (.wakeup selector)
                                                   selector))
                               x))))
               close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :context/ws (volatile! [])
            :http/host "localhost"
            :http/scheme :http
            :http/port 10010
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))

   (-> x :context/shutdown! (apply []))
   (-> x :context/ws (deref))
   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.wakeup))
   (-> x :nio/selector (.keys) count)
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (read!))
   (-> x :nio/selector (.keys) (first) (.attachment) :nio/in)
   (->> x :nio/selector (.keys) (map (fn [sk]
                                       (-> sk (.channel) (.close))
                                       (-> sk (.cancel)))) (doall))
   (-> x :nio/selector (.close))
   read-op
   *e
   *ns*

   (in-ns 'jaq.http.xrf.nio)
   (require 'jaq.http.xrf.websocket)

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
   (let [xf (comp
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
   (let [xf (comp
             selector-rf
             (x/time
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
                             (assoc :http/params {:bucket "staging.alpeware-foo-bar.appspot.com"
                                                  :prefix "app/v8"}
                                    :http/host storage/root
                                    :storage/prefix "app/v8"
                                    :appengine/id (str (System/currentTimeMillis))
                                    :appengine/app "alpeware-foo-bar"
                                    :appengine/service :default
                                    :storage/bucket "staging.alpeware-foo-bar.appspot.com"))))
                  (channel-rf
                   (comp
                    ssl-connection
                    (storage/pages-rf
                     (comp
                      storage/list-objects-rf
                      storage/rest-service-rf
                      (ssl/request-ssl-rf http/http-rf)
                      (ssl/receive-ssl-rf json-response)))
                    (map (fn [{:storage/keys [pages]
                               {:keys [items]} :http/json
                               :as x}]
                           #_(prn ::pages pages)
                           (prn ::items (count items))
                           x))
                    (drop-while (fn [{:storage/keys [pages]
                                      {:keys [nextPageToken items]} :http/json
                                      :as x}]
                                  nextPageToken))
                    (map (fn [{:storage/keys [pages]
                               {:keys [items]} :http/json
                               :as x}]
                           (prn ::pages (count pages))
                           x))
                    close-connection))
                  (drop-while (fn [{:storage/keys [pages] :as x}]
                                (nil? pages)))
                  ;; got list of files
                  (fn [rf]
                    (let [objects (volatile! nil)]
                      (fn
                        ([] (rf))
                        ([acc] (rf acc))
                        ([acc {:appengine/keys [app service]
                               :storage/keys [pages bucket]
                               :as x}]
                         (when-not @objects
                           (->> pages (mapcat :items) (vreset! objects)))
                         (-> x
                             (dissoc :http/params :http/headers :http/body
                                     :http/req :http/chunks :http/json
                                     :ssl/engine)
                             (assoc-in [:http/params :app] app)
                             (assoc-in [:http/params :service] service)
                             (assoc :storage/objects @objects)
                             (assoc :http/host appengine/root-url)
                             (->> (rf acc)))))))
                  ;; deploy rest
                  (channel-rf
                   (comp
                    ssl-connection
                    (comp
                     appengine/version-rf
                     appengine/create-version-rf
                     appengine/rest-service-rf
                     (ssl/request-ssl-rf http/http-rf)
                     (ssl/receive-ssl-rf json-response))
                    (map (fn [{:storage/keys [pages]
                               {:keys [items] :as json} :http/json
                               :as x}]
                           (prn ::json json)
                           x))
                    close-connection))
                  ;; operation
                  ;; migrate
                  ))
                close-rf))))]
     (->> [{:context/bip-size (* 10 4096)
            :http/scheme :https
            :http/port 443
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))
   (in-ns 'jaq.http.xrf.nio)

   (-> x :async/thread (.stop))

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
                                   :file/prefix "app/v7"
                                   :file/dir "./target"
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
     (->> [{:context/bip-size (* 10 4096)
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

   ;; uPnP
   (let [host "239.255.255.250"
         port 1900
         types [
                ;;"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
                ;;"urn:schemas-upnp-org:service:WANIPConnection:1"
                ;;"urn:schemas-upnp-org:service:WANPPPConnection:1"
                "ssdp:all"
                ;;"upnp:rootdevice"
                ]
         search (->> types
                     (map (fn [e]
                            (str "M-SEARCH * HTTP/1.1\r\n"
                                 "HOST: " host ":" port "\r\n"
                                 "ST: " e "\r\n"
                                 "MAN: \"ssdp:discover\"\r\n"
                                 "USER-AGENT: alpeware\r\n"
                                 "MX: 2\r\n\r\n"))))
         xf (comp
             selector-rf
             (thread-rf
              (comp
               (select-rf
                (comp
                 (datagram-channel-rf
                  (comp
                   datagram-read-rf
                   datagram-write-rf
                   (datagram-send-rf (comp
                                      (map
                                       (fn [{:http/keys [host port] :as x}]
                                         (assoc x :http/req search)))))
                   (rf/debug-rf ::sent)
                   (rf/repeatedly-rf
                    (datagram-receive-rf (comp
                                          (map (fn [{:keys [byte] :as x}]
                                                 (assoc x :char (char byte))))
                                          header/response-line
                                          header/headers
                                          #_(map (fn [{:keys [headers char] :as x}]
                                                   (prn char headers)
                                                   x))
                                          (take 1)
                                          (map (fn [{:context/keys [devices]
                                                     :keys [headers char]
                                                     {:keys [location usn st]} :headers
                                                     :as x}]
                                                 (vswap! devices conj headers)
                                                 (prn st usn location)
                                                 x))
                                          #_(drop-while (fn [{:keys [char]}]
                                                          true
                                                          #_(not= char \n)))
                                          #_(fn [rf]
                                              (let [val (volatile! nil)
                                                    vacc (volatile! nil)]
                                                (fn
                                                  ([] (rf))
                                                  ([acc] (rf acc))
                                                  ([acc {:keys [char] :as x}]
                                                   (vswap! vacc conj char)
                                                   (cond
                                                     @val
                                                     (->> (assoc x :upnp/gateway @val)
                                                          (rf acc))

                                                     (not= char \n)
                                                     (do
                                                       (vswap! vacc conj char)
                                                       acc)))))))))))))
               close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :context/devices (volatile! nil)
            :http/host host
            :http/port port
            :http/local-port port
            ;;:http/local-host "192.168.1.140"
            ;;:http/local-host "172.17.0.2"
            }]
          (into [] xf)))
   (def x (first *1))
   *1

   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))

   (require 'clojure.pprint)
   (->> x :context/devices (deref) (clojure.pprint/pprint))

   (->> x :context/devices (deref))
   (->> x :context/devices (deref) (map :usn) (set))
   (->> x :context/devices (deref) (map :st) (set))
   (->> x :context/devices (deref) (map :location) (set))
   *e
   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.close))

   (let [locations (->> x :context/devices (deref) (map :location) (set))]
     (->> locations
          (map (fn [uri]
                 (try
                   [(let [[scheme base] (-> uri (string/split #"://"))]
                      (-> base
                          (string/split #"/")
                          (first)
                          (->> (str scheme "://"))))
                    (clojure.xml/parse uri)]
                   (catch Exception e
                     nil))))
          (mapcat (fn [[uri doc]]
                    (let [uri (or (->> (xml-seq doc)
                                       (filter (fn [x] (= :URLBase (:tag x))))
                                       (map :content)
                                       (first)
                                       (first))
                                  uri)]
                      (->> (xml-seq doc)
                           (filter (fn [x] (= :service (:tag x))))
                           (map (fn [{:keys [content]}]
                                  (->> content
                                       (map (fn [node]
                                              [(:tag node) (-> node :content first)]))
                                       (into {:uri uri}))))))))))
   (def services *1)
   (count services)
   (->> services (map :serviceType))
   (last services)

   (->> services
        #_(filter (fn [{:keys [serviceType]}]
                    (re-matches #"(?i).*:(wanipconnection|wanpppconnection):.*"
                                serviceType)))
        (map (fn [{:keys [uri SCPDURL] :as service}]
               (try
                 [service
                  (clojure.xml/parse (str uri SCPDURL))]
                 (catch Exception e
                   nil))))
        (map (fn [[service doc]]
               {:service service
                :actions
                (->> (xml-seq doc)
                     (filter (fn [x] (= :action (:tag x))))
                     (map (fn [{:keys [content]}]
                            (->> content
                                 (map (fn [{:keys [tag content] :as node}]
                                        (cond
                                          (= tag :name)
                                          [tag (first content)]
                                          (= tag :argumentList)
                                          [tag (->> content (map (fn [{:keys [content]}]
                                                                   (->> content
                                                                        (map (fn [node]
                                                                               [(:tag node)
                                                                                (-> node :content first)]))
                                                                        (into {})))))])))
                                 (into {})))))
                :state
                (->> (xml-seq doc)
                     (filter (fn [x] (= :stateVariable (:tag x))))
                     (map (fn [{:keys [content]}]
                            (->> content
                                 (map (fn [{:keys [tag content] :as node}]
                                        (cond
                                          (contains? #{:name :dataType :defaultValue} tag)
                                          [tag (first content)]
                                          (= tag :allowedValueList)
                                          [tag (->> content (map (fn [node]
                                                                   (-> node :content first)))
                                                    #_(into {}))])))
                                 (into {})))))})))
   (def scp *1)
   (->> scp first :actions (map :name))

   (->> scp
        (filter (fn [{:keys [service]}]
                  (->> service
                       :serviceType
                       (re-matches #"(?i).*:(wanipconnection|wanpppconnection):.*"))))
        (mapcat (fn [{:keys [service actions state]}]
                  (->> actions (filter (fn [{:keys [name]}] (= name "GetExternalIPAddress")))))))

   ;; SOAP request body
   (let [service (->> services (filter (fn [{:keys [serviceType]}]
                                         (string/includes? serviceType "WANIP")))
                      (first))
         service-type (:serviceType service)
         action  "DeletePortMapping" #_"GetExternalIPAddress" #_"AddPortMapping" #_"GetSpecificPortMappingEntry" #_"GetGenericPortMappingEntry"
         args  #_{:NewPortMappingIndex "0"} {:NewRemoteHost "" :NewProtocol "TCP"
                                             :NewExternalPort "8080"} #_{:NewRemoteHost "" :NewProtocol "TCP" :NewExternalPort "8080"
                                                                         :NewInternalClient "192.168.1.140" :NewInternalPort "8080"
                                                                         :NewEnabled "1" :NewPortMappingDescription "alpeware"
                                                                         :NewLeaseDuration "0"}
         soap (->> {:tag :SOAP-ENV:Envelope :attrs {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope"
                                                    :SOAP-ENV:encodingStyle "http://schemas.xmlsoap.org/soap/encoding/"}
                    :content [{:tag :SOAP-ENV:Body
                               :content [{:tag (str "m:" action) :attrs {"xmlns:m" service-type}
                                          :content (->> args (map (fn [[k v]]
                                                                    {:tag k :content [v]})))}]}]}
                   (clojure.xml/emit)
                   (with-out-str))
         soap (string/replace soap "\n" "")
         path (-> service :controlURL)
         [host port] (-> service :uri (string/replace "http://" "") (string/split #":"))
         port (Integer/parseInt port)
         xf (comp
             selector-rf
             (thread-rf
              (comp
               (select-rf
                (comp
                 (channel-rf
                  (comp
                   read-rf
                   write-rf
                   (send-rf (comp
                             (map
                              (fn [{:http/keys [host port] :as x}]
                                (prn soap)
                                (assoc x
                                       :http/headers {:SOAPAction (str service-type "#" action)
                                                      :content-type "text/xml"}
                                       :http/body soap)))
                             http/http-rf))
                   #_(rf/debug-rf ::sent)
                   readable-rf
                   (receive-rf (comp
                                (map (fn [{:keys [byte] :as x}]
                                       (assoc x :char (char byte))))
                                header/response-line
                                header/headers
                                http/chunked-rf
                                http/text-rf
                                body-rf
                                (map (fn [{:http/keys [body]
                                           :keys [status reason headers]
                                           :as x}]
                                       (prn status reason headers)
                                       (prn body)
                                       x))))
                   close-connection))))
               close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/scheme :http
            :http/path path
            :http/port port
            :http/host host
            :http/method :POST
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))

   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (read!))


   (->> services (filter (fn [{:keys [serviceType]}]
                           (string/includes? serviceType "WANIP"))))
   *e

   (require 'clojure.xml)

   (->> (xml-seq doc)
        (filter (fn [x] (= :service (:tag x)))))

   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))
   (-> x :nio/selector (.keys))
   (-> x :nio/selector (.keys) (first))
   (-> x :nio/selector (.keys) (first) (.channel) (.isConnected))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (datagram-receive!))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (assoc :http/req ["foo"]) (datagram-send!))
   (-> x :nio/selector (.keys) (first) (.channel) (.getLocalAddress))
   (-> x :nio/selector (.keys) (first) (.channel) (.socket) (.getLocalPort))

   (into []
         (comp
          (datagram-send-rf (comp
                             (map
                              (fn [{:http/keys [host port] :as x}]
                                (assoc x :http/req ["foo"]))))))
         [(-> x :nio/selector (.keys) (first) (.attachment) :context/x)])

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
   (require 'jaq.http.xrf.nio :reload)

   )
