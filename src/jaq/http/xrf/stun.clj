(ns jaq.http.xrf.stun
  "STUN client implementation.

  Helpful resources:
  - https://tools.ietf.org/html/rfc5389
  - https://gfiber.googlesource.com/vendor/google/platform/+/master/cmds/stun.py
  "
  (:require
   [clojure.string :as string]
   [clojure.xml :as xml]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf])
  (:import
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
   (in-ns 'jaq.http.xrf.stun)
   (require 'jaq.http.xrf.stun :reload)
   *e
   ;; stun
   (let [host host
         req [(encode (ByteBuffer/allocate 20) (:request bind-request) (transaction-id) "")]
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/datagram-channel-rf
                  (comp
                   nio/datagram-read-rf
                   nio/datagram-write-rf
                   (nio/datagram-send-rf (comp
                                          (map
                                           (fn [{:http/keys [host port] :as x}]
                                             (assoc x :http/req req)))))
                   (rf/debug-rf ::sent)
                   (nio/datagram-receive-rf (comp
                                             #_(rf/debug-rf ::received)
                                             (fn header-rf [rf]
                                               (let [header-length 20
                                                     val (volatile! nil)
                                                     vacc (volatile! [])
                                                     assoc-fn (fn [x]
                                                                (let [{:keys [message length cookie id]} @val]
                                                                  (assoc x
                                                                         :stun/message message
                                                                         :stun/length length
                                                                         :stun/cookie cookie
                                                                         :stun/id id)))]
                                                 (fn
                                                   ([] (rf))
                                                   ([acc] (rf acc))
                                                   ([acc {:keys [byte] :as x}]
                                                    (cond
                                                      (< (count @vacc) header-length)
                                                      (do
                                                        (vswap! vacc conj byte)
                                                        (if-not (= (count @vacc) header-length)
                                                          acc
                                                          (do
                                                            (->> @vacc
                                                                 (byte-array)
                                                                 (ByteBuffer/wrap)
                                                                 (decode)
                                                                 (vreset! val))
                                                            (rf acc (assoc-fn x)))))

                                                      :else
                                                      (rf acc (assoc-fn x)))))))
                                             (fn attributes-rf [rf]
                                               (let [once (volatile! false)
                                                     val (volatile! nil)
                                                     vacc (volatile! [])
                                                     assoc-fn (fn [x]
                                                                (let [{:keys []} @val]
                                                                  (assoc x
                                                                         :stun/vacc @vacc)))]
                                                 (fn
                                                   ([] (rf))
                                                   ([acc] (rf acc))
                                                   ([acc {:keys [byte]
                                                          :stun/keys [message length]
                                                          :as x}]
                                                    (cond
                                                      (and (not @once) (> length 0) (empty? @vacc))
                                                      (do
                                                        (vreset! once true)
                                                        acc)

                                                      (< (count @vacc) length)
                                                      (do
                                                        (vswap! vacc conj byte)
                                                        (if-not (= (count @vacc) length)
                                                          acc
                                                          (do
                                                            (->> @vacc
                                                                 (byte-array)
                                                                 (ByteBuffer/wrap)
                                                                 #_(decode-attributes)
                                                                 (vreset! val))
                                                            (rf acc (assoc x
                                                                           :stun/vacc @vacc
                                                                           :stun/response @val)))))

                                                      :else
                                                      (rf acc (assoc x :stun/response @val)))))))
                                             #_(rf/debug-rf ::message)
                                             (map (fn [{:stun/keys [vacc message length cookie id] :as x}]
                                                    (->> (assoc x :stun/buf (->> vacc
                                                                                 (byte-array)
                                                                                 (ByteBuffer/wrap)))
                                                         (decode-attributes))))
                                             (map (fn [{:stun/keys [port ip message length cookie id] :as x}]
                                                    (def y x)
                                                    (prn ::stun port ip message length cookie id)
                                                    x))
                                             (take 1)))))))
               nio/close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/host host
            :http/port port}]
          (into [] xf)))
   (def x (first *1))
   *e

   (->> y :stun/buf)
   (->> y :stun/vacc
        (map unchecked-byte)
        (byte-array)
        (ByteBuffer/wrap)
        (decode))

   (-> x :nio/selector (.keys))
   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))

   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.close))

   (-> x :nio/selector (.keys) (first) (.getLocalPort))
   (-> x :nio/selector (.keys) (first) (.channel) (.getLocalAddress))
   (-> x :nio/selector (.keys) (first) (.channel) (.socket) (.getLocalPort))

   )
