(ns jaq.http.xrf.ice
  "ICE implementation.

  Helpful resources:
  - https://tools.ietf.org/html/rfc5245
  "
  (:require
   [clojure.string :as string]
   [clojure.xml :as xml]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.dtls :as dtls]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.net NetworkInterface]
   [java.nio ByteBuffer]))

;; TODO: add config-rf
(def host "stun.l.google.com")
(def port 19302)
(def magic-cookie 0x2112a442)
(def magic-buf (-> (ByteBuffer/allocate 4) (.putInt magic-cookie) (.flip)))
(def magic-bytes (->> (range (.limit magic-buf)) (map (fn [_] (.get magic-buf)))))
(def servers ["stun.l.google.com"
              "stun1.l.google.com" "stun2.l.google.com"
              "stun3.l.google.com" "stun4.l.google.com"])
(def id-len 12)
;; request types
(def bind-request
  {:request 0x0001
   :indication 0x0011
   :success 0x0101
   :error 0x0111})

(def attributes
  {:mask 0x07ff
   :mapped-address 0x0001
   :username 0x0006
   :message-integrity 0x0008
   :error-code 0x0009
   :unknown-attributes 0x000a
   :realm 0x0014
   :nonce 0x0015
   :xor-mapped-address 0x0020
   :software 0x8022
   :alternate-server 0x8023
   :fingerprint 0x8028})

(def attribute-map
  (->> attributes (map (fn [[k v]] [v k])) (into {})))

(defn transaction-id []
  (->> (range id-len)
       (map (fn [_]
              (rand-int 255)))
       (map unchecked-byte)
       (byte-array)))

(defn encode [buf msg id attr]
  (-> buf
      (.putShort msg)
      (.putShort (count attr))
      (.putInt magic-cookie)
      (.put id)
      (.flip)))

(defn decode [buf]
  (let [msg (.getShort buf)
        length (.getShort buf)
        cookie (.getInt buf)
        id (.getInt buf)]
    {:message msg
     :length length
     :cookie cookie
     :id id}))

#_(
   (->> y :stun/vacc)
   (let [buf (->> y :stun/vacc
                  (byte-array)
                  (ByteBuffer/wrap))]
     (decode buf)
     #_(->> (.getShort buf)
            (Integer/toBinaryString))
     )

   magic-cookie
   )

(def decode-map
  {:xor-mapped-address (fn [{:stun/keys [id buf] :as x}]
                         (let [family (.getShort buf)
                               xport [(.get buf) (.get buf)]
                               ;; TODO: IPv6
                               xip [(.get buf) (.get buf) (.get buf) (.get buf)]]
                           (assoc x
                                  :stun/family family
                                  :stun/port (bit-and
                                              (->> (interleave xport (->> magic-bytes (drop 2)))
                                                   (map (fn [x]
                                                          (bit-and x 0xff)))
                                                   (partition 2)
                                                   (map (fn [[x y]]
                                                          (bit-xor x y)))
                                                   (byte-array)
                                                   (ByteBuffer/wrap)
                                                   (.getShort))
                                              0xffff)
                                  :stun/ip (string/join
                                            "."
                                            (->> (interleave xip magic-bytes)
                                                 (map (fn [x]
                                                        (bit-and x 0xff)))
                                                 (partition 2)
                                                 (map (fn [[x y]]
                                                        (bit-xor x y)))
                                                 (map str))
                                            ))))})

(defn decode-attributes [{:stun/keys [id buf] :as x}]
  #_(prn x)
  (let [type (.getShort buf)
        length (.getShort buf)
        attr-fn (some->> type
                         (get attribute-map)
                         (get decode-map))]
    (prn ::atr attr-fn)
    ;; TODO: handle nil
    (->> (assoc x
                :stun/attr-type type
                :stun/attr-length length)
         (attr-fn))))

#_(
   (->> y :stun/vacc)
   (->> y :stun/id)
   (->> (assoc y :stun/buf (->> y :stun/vacc
                                (byte-array)
                                (ByteBuffer/wrap)))
        (decode-attributes))

   (let [id (->> y :stun/id)
         magic-buf (-> (ByteBuffer/allocate 4) (.putInt magic-cookie) (.flip))
         magic-bytes (->> (range (.limit magic-buf)) (map (fn [_] (.get magic-buf))))
         xor-key (+ magic-cookie id)
         buf (->> y :stun/vacc
                  (byte-array)
                  (ByteBuffer/wrap))]
     ;; attribute
     (let [type (.getShort buf)
           length (.getShort buf)]
       [type length (get attribute-map type :undefined)]
       ;; network address
       (let [family (.getShort buf)
             xport [(.get buf) (.get buf)]]
         [family
          (bit-and
           (->> (interleave xport (->> magic-bytes (drop 2)))
                (map (fn [x]
                       (bit-and x 0xff)))
                (partition 2)
                (map (fn [[x y]]
                       (bit-xor x y)))
                (byte-array)
                (ByteBuffer/wrap)
                (.getShort))
           0xffff)
          ;; port
          #_(->> [(bit-xor (.get buf) (->> magic-bytes (drop 2) (first)))
                  (bit-xor (.get buf) (->> magic-bytes (drop 3) (first)))]
                 (byte-array)
                 (ByteBuffer/wrap)
                 (.getShort)
                 )
          ])
       )
     )
   (Integer/toBinaryString magic-cookie)
   (Integer/toHexString magic-cookie)

   (def xip (last *1))
   (->> xip
        (map (fn [x]
               (bit-and x 0xff)))
        #_(map count))

   ;; ipv4
   (let [buf (-> (ByteBuffer/allocate 4) (.putInt magic-cookie) (.flip))
         magic-bytes [(.get buf) (.get buf) (.get buf) (.get buf)]]
     (string/join
      "."
      (->> (interleave xip magic-bytes)
           (map (fn [x]
                  (bit-and x 0xff)))
           (partition 2)
           (map (fn [[x y]]
                  (bit-xor x y)))
           (map str))
      )
     )

   (bit-and -92 0xff)
   (Integer/toBinaryString -92)
   xport
   (->> [(bit-xor -70 -92)
         (bit-xor -123 66)]
        (byte-array)
        (ByteBuffer/wrap)
        (.getShort))

   (->> [(bit-xor -123 -92)
         (bit-xor -70 66)]
        (byte-array)
        (ByteBuffer/wrap)
        (.getShort))

   )

#_(
   (in-ns 'jaq.http.xrf.ice)
   (require 'jaq.http.xrf.ice :reload)
   *e

   ;; dtls client
   (let [host "localhost"
         ;;port 13222
         certs [(dtls/self-cert :cert/alias "server")
                (dtls/self-cert :cert/alias "client")]
         req ["alpeware\n"]
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 #_(nio/datagram-channel-rf
                  (comp ;; server
                   (comp ;; ssl connection
                    (map (fn [{:ssl/keys [cert] :as x}]
                           (assoc x :ssl/cert (first cert))))
                    dtls/ssl-rf
                    nio/datagram-read-rf
                    (map (fn [{:nio/keys [address] :as x}]
                           (if address
                             (assoc x
                                    :http/host (.getHostName address)
                                    :http/port (.getPort address))
                             x)))
                    nio/datagram-write-rf
                    ;; need to register for both writable/readable
                    (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                                  (nio/read-writable! selection-key)
                                  x))
                    dtls/handshake-rf)
                   #_(rf/debug-rf ::handshake)
                   nio/readable-rf
                   (dtls/receive-ssl-rf (comp
                                             #_(rf/debug-rf ::received)
                                             (map (fn [{:keys [byte]
                                                        :ssl/keys [engine]
                                                        :as x}]
                                                    (prn ::server byte)
                                                    x))
                                             (drop-while (fn [{:keys [byte]}]
                                                           (not= 10 byte)))))
                   (comp
                    nio/writable-rf
                    (dtls/request-ssl-rf (comp
                                          #_(rf/debug-rf ::sent)
                                          (map
                                           (fn [{:http/keys [host port] :as x}]
                                             (assoc x :http/req req)))))
                    (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                  (.hasRemaining (block)))))
                   nio/close-connection))
                 (map (fn [x]
                        (-> x
                            (dissoc :ssl/engine :http/local-port :nio/selection-key
                                    :nio/channel :ssl/mode)
                            (assoc :ssl/mode :client))))
                 (nio/datagram-channel-rf
                  (comp ;; client
                   (comp ;; ssl connection
                    (map (fn [{:ssl/keys [cert] :as x}]
                           (assoc x :ssl/cert (last cert))))
                    dtls/ssl-rf
                    nio/datagram-read-rf
                    (map (fn [{:nio/keys [address] :as x}]
                           (if address
                             (assoc x
                                    :http/host (.getHostName address)
                                    :http/port (.getPort address))
                             x)))
                    nio/datagram-write-rf
                    ;; need to register for both writable/readable
                    (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                                  (nio/read-writable! selection-key)
                                  x))
                    dtls/handshake-rf)
                   nio/writable-rf
                   (dtls/request-ssl-rf (comp
                                          (map
                                           (fn [{:ssl/keys [engine]
                                                 :as x}]
                                             (assoc x :http/req req)))))
                   (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                 (.hasRemaining (block))))
                   ;; clearing out buffer
                   (rf/once-rf (fn [{{:keys [reserve commit block decommit] :as bip} :nio/in :as x}]
                                 (loop [bb (block)]
                                   (when (.hasRemaining bb)
                                     (-> bb (.position (.limit bb)) (decommit))
                                     (prn ::clearing bb)
                                     (recur (block))))
                                 x))
                   #_(rf/debug-rf ::sent)
                   (comp
                    nio/readable-rf
                    (dtls/receive-ssl-rf (comp
                                          #_(rf/debug-rf ::received)
                                          (map (fn [{:keys [byte] :as x}]
                                                 (prn ::client byte)
                                                 x))
                                          (drop-while (fn [{:keys [byte]}]
                                                        (not= 10 byte))))))
                   nio/close-connection))))
               nio/close-rf)))]
     (let [port 37104
           host "192.168.1.140"]
       (->> [{:context/bip-size (* 20 4096)
              :ssl/packet-size 1024
              :ssl/certs certs
              :ssl/mode :server
              :http/host host
              :http/port port
              :http/local-port port}]
            (into [] xf))))
   (def x (first *1))
   *e
   (in-ns 'jaq.http.xrf.ice)
   (ns-unmap *ns* 'y)
   (->> y :ssl/engine (.getSSLContext))
   (->> y :byte)

   (->> x :ssl/certs (filter (fn [{alias :cert/alias}] (= alias "server"))) (first) :cert/private-key)
   (-> x :nio/selector (.keys))
   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))

   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.close))

   (-> x :nio/selector (.keys) (first))
   (-> x :nio/selector (.keys) (first) (.channel) (.getLocalAddress))
   (-> x :nio/selector (.keys) (first) (.channel) (.socket) (.getLocalPort))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x :nio/out)
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (nio/datagram-receive!))
   (-> x :nio/selector (.keys) (first) (.attachment) :context/x (nio/datagram-send!))

   (-> x :nio/selector (.keys) (last))
   (-> x :nio/selector (.keys) (last) (.channel) (.getLocalAddress))
   (-> x :nio/selector (.keys) (last) (.channel) (.socket) (.getLocalPort))
   (-> x :nio/selector (.keys) (last) (.attachment) :context/x (nio/datagram-send!))
   (-> x :nio/selector (.keys) (last) (.attachment) :context/x (nio/datagram-receive!))

   )


#_(

   ;; ice

   ;; get all unique ip addresses from all interfaces
   (->> (NetworkInterface/getNetworkInterfaces)
        (enumeration-seq)
        (mapcat (fn [e]
               (->> (.getInetAddresses e)
                    (enumeration-seq)
                    (map (fn [f] (.getHostAddress f))))))
        (set))

   ;; listen


   )
