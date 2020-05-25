(ns jaq.http.xrf.stun
  "STUN client implementation.

  Helpful resources:
  - https://tools.ietf.org/html/rfc5389
  - https://gfiber.googlesource.com/vendor/google/platform/+/master/cmds/stun.py
  - https://tools.ietf.org/html/draft-thatcher-ice-network-cost-00
  "
  (:require
   [clojure.string :as string]
   [clojure.xml :as xml]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.nio ByteBuffer]
   [javax.crypto.spec SecretKeySpec]
   [javax.crypto Mac]))

;; TODO: add config-rf
(def hash-algo "HmacSHA1")
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
   :priority 0x0024
   :use-candidate 0x0025
   :software 0x8022
   :alternate-server 0x8023
   :fingerprint 0x8028
   :ice-controlled 0x8029
   :ice-controlling 0x802a
   ;; https://mailarchive.ietf.org/arch/msg/ice/gOAus-n6Ll3hfTfBC6zVd6_VTkE/
   :network-cost 0xc057})

(def attribute-map
  (->> attributes (map (fn [[k v]] [v k])) (into {})))

(defn transaction-id []
  (->> (range id-len)
       (map (fn [_]
              (rand-int 255)))
       (map unchecked-byte)
       (byte-array)))

(def encode-map
  {:xor-mapped-address (fn [{:stun/keys [buf attr id family port ip] :as x}]
                         (let [attr-type (get attributes attr)
                               attr-length 8
                               xport [(bit-shift-right port 8) (bit-and port 0xff)]
                               ;; TODO: IPv6
                               xip (->> (string/split ip #".") (map (fn [x] (Integer/parseInt x))) (map unchecked-byte))]
                           (-> buf
                               (.putShort attr-type)
                               (.putShort attr-length)
                               (.putShort family))
                           (->> (interleave xport (->> magic-bytes (drop 2)))
                                (map (fn [x]
                                       (bit-and x 0xff)))
                                (partition 2)
                                (map (fn [[x y]]
                                       (bit-xor x y)))
                                (map (fn [x]
                                       (.put buf x)))
                                (doall))
                           (->> (interleave xip magic-bytes)
                                (map (fn [x]
                                       (bit-and x 0xff)))
                                (partition 2)
                                (map (fn [[x y]]
                                       (bit-xor x y)))
                                (map (fn [x]
                                       (.put buf x)))
                                (doall))
                           buf))
   :username (fn [{:stun/keys [buf attr username] :as x}]
               (let [attr-type (get attributes attr)
                     attr-length (count username)
                     padding (-> attr-length (mod -4) -)]
                 (-> buf
                     (.putShort attr-type)
                     (.putShort attr-length)
                     (.put (.getBytes username)))
                 (run! (fn [_] (.put buf 0)) (range padding))
                 buf))
   :message-integrity (fn [{:stun/keys [buf password] :as x}]
                        (let [attr-type (get attributes attr)
                              attr-length 20
                              secret-key (SecretKeySpec. (.getBytes password) hash-algo)
                              mac (Mac/getInstance hash-algo)]
                          (.init mac secret-key)
                          (.update mac message)
                          (.put buf (.doFinal mac))))
   :fingerprint (fn [{:stun/keys [attr-length buf] :as x}]
                  (let [;; see https://tools.ietf.org/html/rfc5389#section-15.5
                        xor-bytes [0x53 0x54 0x55 0x4e]
                        xcrc-32 (->> (range)
                                    (take attr-length)
                                    (map (fn [_] (.get buf)))
                                    (map (fn [e] (bit-and e 0xff))))
                        crc-32 (->> (interleave xcrc-32 xor-bytes)
                                    (partition 2)
                                    (map (fn [[x y]]
                                           (bit-xor x y)))
                                    (doall))
                        padding (-> attr-length (mod -4) -)]
                    (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                    (assoc x :stun/crc-32 crc-32)))})

(defn encode [{:stun/keys [buf msg id attributes] :as x}]
  ;; header
  (-> buf
      ;; message type
      (.putShort msg)
      ;; remember
      (.mark)
      ;; dummy length
      (.putShort 0)
      ;; magic cookie
      (.putInt magic-cookie)
      ;; transaction id
      (.put id))
  (doseq [attr attributes]
    (-> (get encode-map attr) (apply [(assoc x :stun/attr attr)])))
  ;; update header length
  (let [end (.position buf)
        ;; should be a multiple of 4
        length (- end 20)]
    (-> buf
        (.reset)
        (.putShort length)
        (.position end)
        (.flip))))

#_(
   *e
   (encode (ByteBuffer/allocate 20) (:request bind-request) (transaction-id) "")
   (let [buf (ByteBuffer/allocate 20)]
     (-> buf
         (.putShort 1)
         (.mark)
         (.putShort 2)
         (.putInt magic-cookie)
         (.reset)
         (.putShort 3)
         (.position 8)
         (.putShort 5)
         (.reset)
         #_(.flip)))
   )

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
                                                          (prn x)
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
                                                 (map str))))))
   :username (fn [{:stun/keys [attr-length buf] :as x}]
               (let [username (->> (range)
                                   (take attr-length)
                                   (map (fn [_] (.get buf)))
                                   (map (fn [e] (bit-and e 0xff)))
                                   (map char)
                                   (apply str))
                     padding (-> attr-length (mod -4) -)]
                 (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                 (assoc x :stun/username username)))
   :error-code (fn [{:stun/keys [attr-length buf] :as x}]
                 (let [reserved (.getShort buf)
                       code (-> buf (.get) (bit-and 0xff))
                       number (-> buf (.get) (bit-and 0xff))
                       error-code (-> code (* 100) (+ number))
                       reason (->> (range)
                                   (take attr-length)
                                   (map (fn [_] (.get buf)))
                                   (map (fn [e] (bit-and e 0xff)))
                                   (map char)
                                   (apply str))
                     padding (-> attr-length (mod -4) -)]
                 (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                 (assoc x
                        :stun/error-code error-code
                        :stun/reason reason)))
   :network-cost (fn [{:stun/keys [attr-length buf] :as x}]
                   (let [network-id (-> (.getShort buf) (bit-and 0xffff))
                         network-cost (-> (.getShort buf) (bit-and 0xffff))
                         padding (-> attr-length (mod -4) -)]
                     (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                     (assoc x
                            :stun/network-id network-id
                            :stun/network-cost network-cost)))
   :ice-controlling (fn [{:stun/keys [attr-length buf] :as x}]
                      (let [tiebreaker (-> (.getLong buf) #_(bit-and 0xffffffffffffffff))
                            padding (-> attr-length (mod -4) -)]
                        (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                        (assoc x
                               :ice/role :controlling
                               :ice/tiebreaker tiebreaker)))
   :use-candidate (fn [{:stun/keys [attr-length buf] :as x}]
                    (let []
                      (assoc x
                             :ice/candidate :use)))
   :priority (fn [{:stun/keys [attr-length buf] :as x}]
               (let [priority (-> (.getInt buf) (bit-and 0xffffffff))]
                 (assoc x
                        :ice/priority priority)))
   :message-integrity (fn [{:stun/keys [attr-length buf] :as x}]
                        (let [sha1 (->> (range)
                                        (take attr-length)
                                        (map (fn [_] (.get buf)))
                                        (map (fn [e] (bit-and e 0xff)))
                                        (doall))
                              padding (-> attr-length (mod -4) -)]
                          (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                          (assoc x :stun/hmac-sha1 sha1)))
   :fingerprint (fn [{:stun/keys [attr-length buf] :as x}]
                  (let [;; see https://tools.ietf.org/html/rfc5389#section-15.5
                        xor-bytes [0x53 0x54 0x55 0x4e]
                        xcrc-32 (->> (range)
                                    (take attr-length)
                                    (map (fn [_] (.get buf)))
                                    (map (fn [e] (bit-and e 0xff))))
                        crc-32 (->> (interleave xcrc-32 xor-bytes)
                                    (partition 2)
                                    (map (fn [[x y]]
                                           (bit-xor x y)))
                                    (doall))
                        padding (-> attr-length (mod -4) -)]
                    (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                    (assoc x :stun/crc-32 crc-32)))})

(defn decode-attributes [{:stun/keys [id buf] :as x}]
  (let [type (bit-and (.getShort buf) 0xffff)
        length (bit-and (.getShort buf) 0xffff)
        attr-kw (get attribute-map type)
        attr-fn (or (get decode-map attr-kw)
                    (fn [{:stun/keys [attr-type attr-length buf] :as x}]
                      (let [padding (-> attr-length (mod -4) -)]
                        (prn "Skipping unknown attribute" attr-type attr-length attr-kw)
                        (-> buf (.position (+ (.position buf) attr-length padding)))
                        x)))]
    (prn ::processing attr-kw length)
    (->> (assoc x
                :stun/attr-type type
                :stun/attr-length length)
         (attr-fn))))

#_(

   (let [buf (->> y :stun/vacc
                  (byte-array)
                  (ByteBuffer/wrap))]
     (loop [x' (->> (assoc y :stun/buf buf)
                    (decode-attributes))]
       (if-not (.hasRemaining buf)
         x'
         (recur (decode-attributes x')))))

   )

#_(
   *e
   (-> y (decode-attributes))
   (-> y :stun/buf (.rewind))
   (-> y :stun/buf)
   (-> y :stun/buf (.get) (bit-and 0xff))
   (-> y :stun/buf (.getShort) (bit-and 0xffff))
   (->> y :stun/vacc (drop (.position (:stun/buf y))) (map (fn [e] (bit-and e 0xff))) (map (fn [e] (Integer/toHexString e))))

   (-> y :stun/buf (.position 60))
   (-> y :stun/username)
   (-> y :stun/attr-length)
   (-> y :nio/address)
   (-> y :stun/message)
   (-> y :stun/id)
   (-> y :stun/cookie)
   (-> y :stun/length)
   (->> y :stun/vacc (count))
   (->> y :stun/vacc (drop (.position (:stun/buf y))) (map (fn [e] (bit-and e 0xff))) (map (fn [e] (Integer/toHexString e))))
   (->> [0x87 0x25] (byte-array) (ByteBuffer/wrap) (.getShort) (bit-and 0xffff))
   (->> y :stun/id)
   (->> (assoc y :stun/buf (->> y :stun/vacc
                                (byte-array)
                                (ByteBuffer/wrap)))
        (decode-attributes))

   ;; port 34597
   (let [buf (-> (ByteBuffer/allocate 4) (.putInt 34597) (.flip))]
     (.position buf 2)
     (bit-and 0xffff (.getShort buf))
     #_(->> (range) (take 4) (map (fn [_] (bit-and 0xff (.get buf))))))

   (Integer/toHexString 34597)
   (Integer/toHexString 92)

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
   (let [req [(encode (ByteBuffer/allocate 20) (:request bind-request) (transaction-id) "")]
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
                                             (take 1)
                                             ))))))
               nio/close-rf)))]
     (let [host "192.168.1.140"
           port 37104]
       (->> [{:context/bip-size (* 1 4096)
              :http/host host
              :http/port port
              :http/local-port 2222}]
            (into [] xf))))
   (def x (first *1))
   *e

   (->> y :stun/buf)
   (->> y :stun/vacc
        (map unchecked-byte)
        (byte-array)
        (ByteBuffer/wrap)
        (decode))

   ;; ice
   (let [req [(encode (ByteBuffer/allocate 20) (:request bind-request) (transaction-id) "")]
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/datagram-channel-rf
                  (comp
                   nio/datagram-read-rf
                   #_(map (fn [{:nio/keys [address] :as x}]
                            (if address
                              (assoc x
                                     :http/host (.getHostName address)
                                     :http/port (.getPort address))
                              x)))
                   nio/datagram-write-rf
                   #_(nio/datagram-send-rf (comp
                                            (map
                                             (fn [{:http/keys [host port] :as x}]
                                               (assoc x :http/req req)))))
                   #_(rf/debug-rf ::sent)
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
                                                    (let [buf (->> vacc
                                                                   (byte-array)
                                                                   (ByteBuffer/wrap))]
                                                      (loop [x' (->> (assoc x :stun/buf buf)
                                                                     (decode-attributes))]
                                                        (if-not (.hasRemaining buf)
                                                          x'
                                                          (recur (decode-attributes x')))))))
                                             (map (fn [{:stun/keys [port ip message length cookie id] :as x}]
                                                    (def y x)
                                                    (prn ::stun port ip message length cookie id)
                                                    x))
                                             (take 1)
                                             nio/close-connection))))))
               nio/close-rf)))]
     (let [host "192.168.1.140"
           port 5000]
       (->> [{:context/bip-size (* 1 4096)
              :http/host host
              :http/port port
              :http/local-port 2223}]
            (into [] xf))))
   (def x (first *1))
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

   (-> y :stun/buf)
   (-> y (decode-attributes))
   )
