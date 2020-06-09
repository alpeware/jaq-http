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
   [java.security SecureRandom]
   [java.util.zip CRC32]
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
;; message types
(def messages
  {:request 0x0001
   :indication 0x0011
   :success 0x0101
   :error 0x0111})

(def message-map
  (->> messages (map (fn [[k v]] [v k])) (into {})))

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

(def families {:ipv4 0x01 :ipv6 0x02})

(def family-map
  (->> families (map (fn [[k v]] [v k])) (into {})))

(def secure-random (SecureRandom.))

(defn tiebreaker []
  (BigInteger. 64 secure-random))

#_(
   (tiebreaker)
   )

(defn transaction-id []
  (->> (range id-len)
       (map (fn [_]
              (rand-int 255)))
       (map unchecked-byte)
       #_(byte-array)))

#_(
   (let [buf (ByteBuffer/allocate 12)
         id (transaction-id)]
     (.put buf (byte-array id)))

   (let [ip "192.168.1.140"]
     (->> (string/split ip ".") #_(map (fn [x] (Integer/parseInt x))) #_(map unchecked-byte)))
   )

(def encode-map
  {:xor-mapped-address (fn [{:stun/keys [buf attr id family port ip] :as x}]
                         (let [attr-type (get attributes attr)
                               attr-length 8
                               address-family (get families family)
                               xport [(bit-shift-right port 8) (bit-and port 0xff)]
                               ;; TODO: IPv6
                               xip (->> (string/split ip #"\.") (map (fn [x] (Integer/parseInt x))) (map unchecked-byte))]
                           (prn ::port port ::ip ip)
                           (-> buf
                               (.putShort attr-type)
                               (.putShort attr-length)
                               (.putShort address-family))
                           (doseq [[x y] (->> (interleave xport (->> magic-bytes (take 2) #_(drop 2)))
                                              (map (fn [x]
                                                     (bit-and x 0xff)))
                                              (partition 2))]
                             (->> (bit-xor x y)
                                  (unchecked-byte)
                                  (.put buf)))
                           (doseq [[x y] (->> (interleave xip magic-bytes)
                                              (mapv (fn [x]
                                                      (bit-and x 0xff)))
                                              (partition 2))]
                             (->> (bit-xor x y)
                                  (unchecked-byte)
                                  (.put buf)))
                           buf))
   :username (fn [{:stun/keys [buf attr username] :as x}]
               (let [attr-type (get attributes attr)
                     attr-length (count username)
                     padding (-> attr-length (mod -4) -)]
                 (prn ::username username)
                 (-> buf
                     (.putShort attr-type)
                     (.putShort attr-length)
                     (.put (.getBytes username)))
                 (run! (fn [_] (.put buf (byte 0))) (range padding))
                 buf))
   :ice-controlling (fn [{:stun/keys [buf attr] :as x}]
                      (let [attr-type (get attributes attr)
                            attr-length 8
                            tiebreaker (tiebreaker)]
                        (-> buf
                            (.putShort attr-type)
                            (.putShort attr-length)
                            (.putLong tiebreaker))))
   :ice-controlled (fn [{:stun/keys [buf attr] :as x}]
                     (let [attr-type (get attributes attr)
                           attr-length 8
                           tiebreaker (tiebreaker)]
                       (-> buf
                           (.putShort attr-type)
                           (.putShort attr-length)
                           (.putLong tiebreaker))))
   :priority (fn [{:stun/keys [buf attr priority] :as x}]
               (let [attr-type (get attributes attr)
                     attr-length 4]
                 (-> buf
                     (.putShort attr-type)
                     (.putShort attr-length)
                     (.putInt priority))))
   :use-candidate (fn [{:stun/keys [buf attr] :as x}]
                    (let [attr-type (get attributes attr)
                          attr-length 0]
                      (-> buf
                          (.putShort attr-type)
                          (.putShort attr-length))))
   :message-integrity (fn [{:stun/keys [buf attr password] :as x}]
                        (let [attr-type (get attributes attr)
                              attr-length 20
                              pos (.position buf)
                              length (-> pos (+ 2) (+ 2) (+ attr-length) (- 20))
                              secret-key (SecretKeySpec. (.getBytes password) hash-algo)
                              mac (Mac/getInstance hash-algo)]
                          (prn ::password password)
                          ;; update length field before calculation
                          (-> buf
                              (.reset)
                              (.putShort length)
                              (.position pos))
                          ;; calculate hash
                          (.init mac secret-key)
                          (.update mac (-> buf (.duplicate) (.flip)))
                          ;; add attribute
                          (-> buf
                              (.putShort attr-type)
                              (.putShort attr-length)
                              (.put (.doFinal mac)))))
   :fingerprint (fn [{:stun/keys [buf attr] :as x}]
                  (let [attr-type (get attributes attr)
                        attr-length 4
                        pos (.position buf)
                        length (-> pos (+ 2) (+ 2) (+ attr-length) (- 20))
                        crc32 (CRC32.)
                        ;; see https://tools.ietf.org/html/rfc5389#section-15.5
                        xor-bytes [0x53 0x54 0x55 0x4e]]
                    (prn ::length length)
                    ;; update length field before calculation
                    (-> buf
                        (.reset)
                        (.putShort length)
                        (.position pos))
                    ;; calculate checksum
                    (.update crc32 (-> buf (.duplicate) (.flip)))
                    ;; add attribute
                    (-> buf
                        (.putShort attr-type)
                        (.putShort attr-length))
                    ;; add crc
                    (doseq [[x y] (-> crc32
                                      (.getValue)
                                      (biginteger)
                                      (.toByteArray)
                                      (interleave xor-bytes)
                                      (->> (partition 2)))]
                      (->> (bit-xor x y)
                           (unchecked-byte)
                           (.put buf)))
                    buf))})

#_(
   (in-ns 'jaq.http.xrf.stun)
   *e
   (let [xor-bytes [0x53 0x54 0x55 0x4e]
         crc32 (CRC32.)]
     (.update crc32 (.getBytes "foobar"))
     #_(->> crc32 (.getValue) (biginteger) (.toByteArray))
     (-> crc32 (.getValue) (biginteger) (.toByteArray)
         (interleave xor-bytes)
         (->> (partition 2))))

   [[0x00 0x01 0x00 0x58
     0x21 0x12 0xa4 0x42
     0xb7 0xe7 0xa7 0x01 0xbc 0x34 0xd6 0x86 0xfa 0x87 0xdf 0xae
     0x80 0x22 0x00 0x10]
    (->> "STUNtestclient  " (map int) (map unchecked-byte) (doall))
    [
     0x00 0x24 0x00 0x04
     0x6e 0x00 0x01 0xff
     0x80 0x29 0x00 0x08
     0x93 0x2f 0xf9 0xb1 0x51 0x26 0x3b 0x36
     0x00 0x06 0x00 0x09
     0x65 0x76 0x74 0x6a 0x3a 0x68 0x36 0x76 0x59 0x20 0x20 0x20
     0x00 0x08 0x00 0x14
     0x9a 0xea 0xa7 0x0c 0xbf 0xd8 0xcb 0x56 0x78 0x1e 0xf2 0xb5
     0xb2 0xd3 0xf2 0x49 0xc1 0xb5 0x71 0xa2
     0x80 0x28 0x00 0x04
     0xe5 0x7a 0x3b 0xcf]]

   (let [message [0x01 0x01 0x00 0x3c
                  0x21 0x12 0xa4 0x42
                  0xb7 0xe7 0xa7 0x01 0xbc 0x34 0xd6 0x86 0xfa 0x87 0xdf 0xae
                  0x80 0x22 0x00 0x0b
                  0x74 0x65 0x73 0x74 0x20 0x76 0x65 0x63 0x74 0x6f 0x72 0x20
                  0x00 0x20 0x00 0x08
                  0x00 0x01 0xa1 0x47 0xe1 0x12 0xa6 0x43
                  0x00 0x08 0x00 0x14
                  0x2b 0x91 0xf5 0x99 0xfd 0x9e 0x90 0xc3 0x8c 0x74 0x89 0xf9
                  0x2a 0xf9 0xba 0x53 0xf0 0x6b 0xe7 0xd7
                  0x80 0x28 0x00 0x04
                  0xc0 0x7d 0x4c 0x96]
         buf (->> message (map unchecked-byte) (byte-array) (ByteBuffer/wrap))
         {:keys [message length id]} (decode buf)
         {:stun/keys [crc-32] :as x} (loop [x' (->> {:stun/buf buf :stun/message message :stun/length length :stun/id id}
                                                    (decode-attributes))]
                                       (if-not (.hasRemaining buf)
                                         x'
                                         (recur (decode-attributes x'))))
         _ (.clear buf)
         _ (->> (assoc x :stun/attributes [:xor-mapped-address :fingerprint])
                (encode))
         _ (decode buf)
         {crc :stun/crc-32 :as y} (loop [x' (->> {:stun/buf buf}
                                                 (decode-attributes))]
                                    (if-not (.hasRemaining buf)
                                      x'
                                      (recur (decode-attributes x'))))]
     [crc-32 crc length])

   (let [xport [0xa1 0x47]]
     (->> (interleave xport (->> magic-bytes (take 2) #_(drop 2)))
          (map (fn [x]
                 (bit-and x 0xff)))
          (partition 2)
          (map (fn [[x y]]
                 (bit-xor x y)))
          (byte-array)
          (ByteBuffer/wrap)
          (.getShort)
          (bit-and 0xffff)))

   *e
   )

(defn encode [{:stun/keys [buf message id attributes] :as x}]
  ;; header
  (prn ::header (get messages message))
  (-> buf
      ;; message type
      (.putShort (get messages message))
      ;; remember
      (.mark)
      ;; dummy length
      (.putShort 0)
      ;; magic cookie
      (.putInt magic-cookie)
      ;; transaction id
      (.put (byte-array id)))
  (doseq [attr attributes]
    (prn ::encoding attr)
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
   (->> y :stun/id (byte-array))
   (->> y :stun/message (get messages))
   (->> y :stun/buf)
   (let [{:stun/keys [buf message id attributes]} y]
     (-> buf
         ;; message type
         (.putShort (get messages message))
         ;; remember
         (.mark)
         ;; dummy length
         (.putShort 0)
         ;; magic cookie
         (.putInt magic-cookie)
         ;; transaction id
         (.put (byte-array id))))

   (encode y)
   *e
   (encode (ByteBuffer/allocate 20) (:request bind-request) (transaction-id) "")
   (let [buf (ByteBuffer/allocate 100)
         id (transaction-id)
         x {:stun/buf buf :stun/message :success :stun/id id
            :stun/family :ipv4 :stun/port 2222 :stun/ip "192.168.1.140"
            :stun/username "foobar:barfoo"
            :stun/password "1234567890123456789012"
            :stun/attributes [:xor-mapped-address :username :ice-controlled :message-integrity :fingerprint]}
         buf (encode x)
         {:keys [message id length]} (->> buf (decode))
         x {:stun/buf buf
            :stun/message message
            :stun/length length
            :stun/id id
            :stun/password "1234567890123456789012"}]
     #_(->> {:stun/buf buf
             :stun/message message
             :stun/id id
             :stun/password "1234567890123456789012"}
            (decode-attributes)
            #_(decode-attributes))
     (loop [x' (->>  (assoc x :stun/buf buf)
                     (decode-attributes))]
       (if-not (.hasRemaining buf)
         x'
         (recur (decode-attributes x'))))
     #_buf
     )
   *e
   )

(defn decode [buf]
  (let [msg (.getShort buf)
        length (.getShort buf)
        cookie (.getInt buf)
        id (->> (range id-len) (mapv (fn [_] (.get buf))))]
    {:message (get message-map msg)
     :length length
     :cookie cookie
     :id id}))

#_(
   (->> y :stun/buf (.rewind) (decode))
   (->> y :stun/vacc)
   (let [buf (->> y :stun/vacc
                  (byte-array)
                  (ByteBuffer/wrap))]
     (decode buf)
     #_(->> (.getShort buf)
            (Integer/toBinaryString))
     )
   (let [buf (->> y :stun/buf (.rewind))]
     (decode buf)
     #_(->> (.getShort buf)
            (Integer/toBinaryString))
     )
   magic-cookie
   *e
   )

(def decode-map
  {:xor-mapped-address (fn [{:stun/keys [id buf] :as x}]
                         (let [family (.getShort buf)
                               xport [(.get buf) (.get buf)]
                               ;; TODO: IPv6
                               xip [(.get buf) (.get buf) (.get buf) (.get buf)]]
                           (assoc x
                                  :stun/family (get family-map family)
                                  :stun/port (->> (interleave xport (->> magic-bytes (take 2) #_(drop 2)))
                                                  (map (fn [x]
                                                         (bit-and x 0xff)))
                                                  (partition 2)
                                                  (map (fn [[x y]]
                                                         (bit-xor x y)))
                                                  (byte-array)
                                                  (ByteBuffer/wrap)
                                                  (.getShort)
                                                  (bit-and 0xffff))
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
                 (run! (fn [_] (.get buf)) (range padding))
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
   :ice-controlled (fn [{:stun/keys [attr-length buf] :as x}]
                     (let [tiebreaker (-> (.getLong buf) #_(bit-and 0xffffffffffffffff))
                           padding (-> attr-length (mod -4) -)]
                       (->> (range) (take padding) (map (fn [_] (.get buf))) (doall))
                       (assoc x
                              :ice/role :controlled
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
                        (prn "Skipping unknown attribute" attr-type attr-length attr-kw buf)
                        (-> buf (.position (+ (.position buf) attr-length padding)))
                        x)))]
    (prn ::processing type attr-kw length)
    (->> (assoc x
                :stun/attr-type type
                :stun/attr-length length)
         (attr-fn))))

#_(

   (+ 20 8 2 2)
   (def buf (ByteBuffer/allocate 100))
   (let [;;buf (ByteBuffer/allocate 100)
         x {:stun/buf buf :stun/message :success :stun/id (transaction-id)
            :stun/family :ipv4 :stun/port 2222 :stun/ip "192.168.1.140"
            :stun/username "foobar:barfoo"
            :stun/password "1234567890123456789012"
            :stun/attributes [:xor-mapped-address :username :message-integrity :fingerprint]}
         buf (encode x)
         ]
     (->> (.limit buf) (range) (mapv (fn [_] (-> buf (.get) (bit-and 0xff)))))
     )

   (let [_ (.rewind buf)
         {:keys [message id]} (->> buf (decode))]
     (->> {:stun/buf buf
           :stun/message message
           :stun/id id
           :stun/password "1234567890123456789012"}
          (decode-attributes)
          (decode-attributes))
     #_buf
     )

   (let [;;buf (ByteBuffer/allocate 100)
         x {:stun/buf buf :stun/message :success :stun/id (transaction-id)
            :stun/family :ipv4 :stun/port 2222 :stun/ip "192.168.1.140"
            :stun/username "foobar:barfoo"
            :stun/password "1234567890123456789012"
            :stun/attributes [:xor-mapped-address :username :message-integrity :fingerprint]}
         buf (encode x)
         {:keys [message id]} (->> buf (decode))]
     (->> {:stun/buf buf
           :stun/message message
           :stun/id id
           :stun/password "1234567890123456789012"}
          (decode-attributes)
          #_(decode-attributes))
     #_(loop [x' (->>  (assoc x :stun/buf buf)
                       (decode-attributes))]
         (if-not (.hasRemaining buf)
           x'
           (recur (decode-attributes x'))))
     buf
     )

   (let [buf (->> y :stun/vacc
                  (byte-array)
                  (ByteBuffer/wrap))]
     (loop [x' (->> (assoc y :stun/buf buf)
                    (decode-attributes))]
       (if-not (.hasRemaining buf)
         x'
         (recur (decode-attributes x')))))

   (let [buf (->> y :stun/buf)]
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
   (let [req [(encode {:stun/buf (ByteBuffer/allocate 100)
                       :stun/message :request
                       :stun/id (transaction-id)
                       :stun/attributes [] })]
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/datagram-channel-rf
                  (comp
                   nio/datagram-read-rf
                   (map (fn [{:nio/keys [address] :as x}]
                          (if address
                            (assoc x
                                   :http/host (.getHostName address)
                                   :http/port (.getPort address))
                            x)))
                   nio/datagram-write-rf
                   (nio/datagram-send-rf
                    (comp
                     (map
                      (fn [{:http/keys [host port] :as x}]
                        (assoc x :http/req req)))))
                   (rf/debug-rf ::sent)
                   (nio/datagram-receive-rf
                    (comp
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
                              ;; TODO: improve
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
                     nio/close-connection))))
                 nio/writable-rf))
               nio/close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/host host
            :http/port port
            :http/local-port 2222}]
          (into [] xf)))
   (def x (first *1))
   *e

   (-> x :nio/selector (.keys))
   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))
   (-> x :nio/selector (.close))

   (->> y :stun/buf)
   (->> y :stun/vacc
        (map unchecked-byte)
        (byte-array)
        (ByteBuffer/wrap)
        (decode))

   ;; ice
   (let [req []
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/datagram-channel-rf
                  (comp
                   nio/datagram-read-rf
                   (map (fn [{:nio/keys [address] :as x}]
                          (if address
                            (assoc x
                                   :http/host (.getHostName address)
                                   :http/port (.getPort address))
                            x)))
                   nio/datagram-write-rf
                   (rf/repeatedly-rf
                    (comp
                     (nio/datagram-receive-rf
                      (comp
                       (rf/one-rf :udp/protocol (comp
                                                 (map (fn [{:keys [byte] :as x}]
                                                        ;; https://chromium.googlesource.com/external/webrtc/trunk/webrtc/+/63d5096b4b20303ca54f86c5f502b6826486e578/p2p/base/dtlstransportchannel.cc#30
                                                        (if (and (> byte 19) (< byte 64))
                                                          :dtls
                                                          :stun)))))
                       (rf/choose-rf
                        :udp/protocol
                        {:stun (comp
                                (fn header-rf [rf]
                                  (let [header-length 20
                                        val (volatile! nil)
                                        vacc (volatile! [])
                                        assoc-fn (fn [x]
                                                   (let [{:keys [message length cookie id]} @val]
                                                     (assoc x
                                                            :stun/header @vacc
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
                                                            :stun/body @vacc
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
                                (map (fn [{:stun/keys [vacc message length cookie id] :as x}]
                                       (let [buf (->> vacc
                                                      (byte-array)
                                                      (ByteBuffer/wrap))]
                                         (if (> length 0)
                                           ;; TODO: improve
                                           (loop [x' (->> (assoc x :stun/buf buf)
                                                          (decode-attributes))]
                                             (if-not (.hasRemaining buf)
                                               x'
                                               (recur (decode-attributes x'))))
                                           x))))
                                (map (fn [{:stun/keys [port ip message length cookie id] :as x}]
                                       (prn ::stun message length cookie id)
                                       x))
                                (take 1)
                                (rf/debug-rf ::request))
                         :dtls (comp
                                (rf/debug-rf ::dtls))})))
                     ;; wait for request
                     (drop-while (fn [{:stun/keys [message]}]
                                   (prn ::message message)
                                   (nil? message)))
                     (rf/one-rf :stun/message (comp
                                               (map (fn [{:stun/keys [message] :as x}]
                                                      (prn ::one message)
                                                      x))
                                               (map :stun/message)))
                     #_(rf/one-rf :stun/username (comp
                                                (map :stun/username)))
                     #_(rf/one-rf :stun/id (comp
                                          (map :stun/id)))
                     (rf/choose-rf
                      :stun/message
                      {:request (comp
                                 ;; create response
                                 #_(rf/debug-rf ::choose)
                                 (nio/datagram-send-rf
                                  (comp
                                   (map (fn [{:context/keys [buf]
                                              :http/keys [host port]
                                              :as x}]
                                          (assoc x
                                                 :stun/buf (-> buf (.clear))
                                                 :stun/message :success
                                                 :stun/family :ipv4
                                                 :stun/port port
                                                 :stun/ip host
                                                 :stun/attributes [:xor-mapped-address #_:fingerprint])))
                                   (map
                                    (fn [{:stun/keys [buf] :as x}]
                                      (assoc x :http/req [(encode x)])))
                                   (rf/debug-rf ::response)))
                                 (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                               (.hasRemaining (block))))
                                 #_nio/close-connection
                                 ;; send binding request
                                 nio/writable-rf
                                 (nio/datagram-send-rf
                                  (comp
                                   (map (fn [{:stun/keys [username id] :as x}]
                                          (assoc x :stun/username
                                                 (->> (string/split username #":")
                                                      (reverse)
                                                      (string/join ":")))))
                                   (map (fn [{:context/keys [buf remote-password]
                                              :http/keys [local-port]
                                              :as x}]
                                          (assoc x
                                                 :stun/buf (-> buf (.clear))
                                                 :stun/id (transaction-id)
                                                 :stun/message :request
                                                 :stun/password remote-password
                                                 :stun/family :ipv4
                                                 :stun/port local-port
                                                 :stun/ip "192.168.1.140"
                                                 :stun/attributes [:username :ice-controlled :use-candidate
                                                                   :message-integrity :fingerprint])))
                                   (map
                                    (fn [{:stun/keys [buf] :as x}]
                                      (assoc x :http/req [(encode x)])))
                                   (rf/debug-rf ::binding)))
                                 (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                               (.hasRemaining (block))))
                                 (rf/debug-rf ::sent)
                                 nio/readable-rf)
                       :success (comp
                                 (rf/debug-rf ::success)
                                 (map (fn [x]
                                        x)))
                       :error (comp
                               (rf/debug-rf ::error))})
                     (rf/debug-rf ::done)))))))
               nio/close-rf)))]
     (let [host "192.168.1.140"
           port 5000]
       (->> [{:context/bip-size (* 1 4096)
              :context/buf (ByteBuffer/allocate 150)
              ;; (connect 2230)
              :context/remote-password "QWKFfZh83blyHK8+yraooRW/"
              :stun/password "1234567890123456789012"
              :http/host host
              :http/port port
              :http/local-port 2230}]
            (into [] xf))))
   (def x (first *1))
   ;; in browser :cljs
   (connect 2230)

   (-> x :context/buf (.rewind) (.get) (bit-and 0xff))
   (-> x :nio/selector (.keys))
   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))
   (-> x :nio/selector (.close))

   (-> x :context/buf (.rewind) (.get))

   (-> y :stun/vacc)
   (-> y :stun/length)
   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.close))

   (-> x :nio/selector (.keys) (first) (.getLocalPort))
   (-> x :nio/selector (.keys) (first) (.channel) (.getLocalAddress))
   (-> x :nio/selector (.keys) (first) (.channel) (.socket) (.getLocalPort))

   (-> y :stun/buf)
   (-> y (decode-attributes))

   (in-ns 'jaq.http.xrf.stun)
   (require 'jaq.http.xrf.stun :reload)

   )
