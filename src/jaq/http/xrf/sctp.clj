(ns jaq.http.xrf.sctp
  "SCTP over UDP implementation.

  Focus is on data channel support.

  Helpful resources:
  - https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13
  - https://tools.ietf.org/html/rfc6951
  - https://tools.ietf.org/html/rfc4960
  - https://tools.ietf.org/html/rfc6525
  - https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml
  - https://github.com/sctplab/usrsctp/
  - https://github.com/pipe/sctp4j
  - https://github.com/IIlllII/bitbreeds-webrtc
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
   [java.nio.charset Charset]
   [java.nio ByteBuffer ByteOrder]
   [java.security SecureRandom]
   [java.util.zip CRC32C]))

;; chunk types
(def chunks
  {:data 0
   :init 1
   :init-ack 2
   :sack 3
   :heartbeat 4
   :hearbeat-ack 5
   :abort 6
   :shutdown 7
   :shutdown-ack 8
   :error 9
   :cookie-echo 10
   :cookie-ack 11
   :ecne 12
   :cwr 13
   :shutdown-complete 14
   ;; https://tools.ietf.org/html/rfc4895
   :auth 15
   ;; https://tools.ietf.org/html/rfc6525
   :re-config 130
   ;; https://tools.ietf.org/html/rfc5061
   :asconf-ack 0x80
   :asconf 0xc1
   ;; https://tools.ietf.org/html/rfc3758
   :forward-tsn 192})

(def chunk-map
  (->> chunks (map (fn [[k v]] [v k])) (into {})))

;; variable parameters
(def parameters
  {:ipv4 5
   :ipv6 6
   :cookie 7
   :cookie-ttl 9
   :hostname 11
   :address-family 12
   ;; https://tools.ietf.org/html/rfc3758#section-3.1
   :forward-tsn 49152
   ;; https://tools.ietf.org/html/rfc5061#section-4.2.7
   :extensions 0x8008
   ;; https://tools.ietf.org/html/rfc4895
   ;; https://tools.ietf.org/id/draft-nagesh-sctp-auth-4895bis-00.html#rfc.section.3.1
   :random 0x8002
   ;; https://tools.ietf.org/id/draft-nagesh-sctp-auth-4895bis-00.html#rfc.section.3.3
   :hmac-algo 0x8004
   ;; https://tools.ietf.org/id/draft-nagesh-sctp-auth-4895bis-00.html#rfc.section.3.2
   :chunks 0x8003
   })

(def parameter-map
  (->> parameters (map (fn [[k v]] [v k])) (into {})))

(def hmacs
  {:sha-1 1
   :sha-256 3})

(def hmac-map
  (->> hmacs (map (fn [[k v]] [v k])) (into {})))

(def protocols
  {;; https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-data-protocol-09
   :webrtc/dcep 50
   ;; https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-data-channel-13
   :webrtc/string 51
   :webrtc/binary 53})

(def protocol-map
  (->> protocols (map (fn [[k v]] [v k])) (into {})))

(def messages
  {:message/ack 2
   :message/open 3})

(def message-map
  (->> messages (map (fn [[k v]] [v k])) (into {})))

(def channels
  "Registered data channel types.

  https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-data-protocol-09#section-8.2.2 "
  {:datachannel/reliable 0x00
   :datachannel/reliable-unordered 0x80
   :datachannel/partial-reliable 0x01
   :datachannel/partial-reliable-unordered 0x81
   :datachannel/partial-reliable-timed 0x02
   :datachannel/partial-reliable-timed-unordered 0x82})

(def channel-map
  (->> channels (map (fn [[k v]] [v k])) (into {})))

(defn decode-header
  "                       SCTP Common Header Format

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Source Port Number        |     Destination Port Number   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Verification Tag                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Checksum                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [buf] :as x}]
  (let [src (.getShort buf)
        dst (.getShort buf)
        tag (-> (.getInt buf) (bit-and 0xffffffff))
        checksum (-> buf (.order ByteOrder/LITTLE_ENDIAN) (.getInt) (bit-and 0xffffffff))]
    (-> buf (.order ByteOrder/BIG_ENDIAN))
    (assoc x
           :sctp/src src :sctp/dst dst
           :sctp/tag tag :sctp/checksum checksum)))

(defn decode-chunk
  "        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                          Chunk Value                          /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [buf] :as x}]
  (let [chunk-type (-> buf (.get) (bit-and 0xff))
        chunk-flags (-> buf (.get) (bit-and 0xff))
        chunk-length (-> buf (.getShort) (bit-and 0xffff))
        chunk-padding (-> chunk-length (mod -4) -)]
    (assoc x
           :sctp/chunk-type chunk-type
           :sctp/chunk-flags chunk-flags
           :sctp/chunk-padding chunk-padding
           :sctp/chunk-length (-> chunk-length (- 4)))))

(def decode-chunk-map
  {:init (fn [{:sctp/keys [buf] :as x}]
           (let [init-tag (-> (.getInt buf) (bit-and 0xffffffff))
                 window (-> (.getInt buf) (bit-and 0xffffffff))
                 outbound (-> buf (.getShort) (bit-and 0xffff))
                 inbound (-> buf (.getShort) (bit-and 0xffff))
                 initial-tsn (-> (.getInt buf) (bit-and 0xffffffff))]
             (assoc x
                    :sctp/init-tag init-tag :sctp/window window
                    :sctp/outbound outbound :sctp/inbound inbound
                    :sctp/initial-tsn initial-tsn)))
   :init-ack (fn [{:sctp/keys [buf] :as x}]
               (let [init-tag (-> (.getInt buf) (bit-and 0xffffffff))
                     window (-> (.getInt buf) (bit-and 0xffffffff))
                     outbound (-> buf (.getShort) (bit-and 0xffff))
                     inbound (-> buf (.getShort) (bit-and 0xffff))
                     initial-tsn (-> (.getInt buf) (bit-and 0xffffffff))]
                 (assoc x
                        :sctp/init-tag init-tag :sctp/window window
                        :sctp/outbound outbound :sctp/inbound inbound
                        :sctp/initial-tsn initial-tsn)))
   :cookie-echo (fn [{:sctp/keys [buf chunk-length] :as x}]
                  (let [cookie (->> (range)
                                    (take chunk-length)
                                    (map (fn [_] (.get buf)))
                                    (map (fn [e] (bit-and e 0xff)))
                                    (doall))]
                    (assoc x :sctp/cookie cookie)))
   :cookie-ack (fn [{:sctp/keys [buf chunk-length] :as x}]
                 (let []
                   x))
   :data (fn [{:sctp/keys [buf chunk-length chunk-flags chunk-padding] :as x}]
           (let [flags (->> {:unordered (bit-test chunk-flags 2)
                             :begining (bit-test chunk-flags 1)
                             :ending (bit-test chunk-flags 0)}
                            (remove (fn [[k v]] (false? v)))
                            (map (fn [[k v]] k))
                            (set))
                 tsn (-> (.getInt buf) (bit-and 0xffffffff))
                 stream (-> buf (.getShort) (bit-and 0xffff))
                 sequence (-> buf (.getShort) (bit-and 0xffff))
                 protocol (-> (.getInt buf) (bit-and 0xffffffff))
                 data (->> (range)
                           (take (- chunk-length 12))
                           (map (fn [_] (.get buf)))
                           (map (fn [e] (bit-and e 0xff)))
                           (doall))]
             (run! (fn [_] (.get buf)) (range chunk-padding))
             (assoc x
                    :sctp/flags flags
                    :sctp/tsn tsn :sctp/stream stream
                    :sctp/sequence sequence :sctp/protocol protocol
                    :sctp/data data)))})

#_(
   (in-ns 'jaq.http.xrf.sctp)
   *e
   *ns*

   (->> {:unordered false :begining false :ending true}
        (remove (fn [[k v]] (false? v)))
        (map (fn [[k v]] k))
        (set))

   )

(def decode-opt-map
  {:ipv4 (fn [{:sctp/keys [param-length param-padding buf] :as x}]
           (let [ip (string/join "."
                                 (->> (range)
                                      (take param-length)
                                      (map (fn [_] (.get buf)))
                                      (map (fn [e] (bit-and e 0xff)))
                                      (map str)
                                      (doall)))]
             #_(run! (fn [_] (.get buf)) (range param-padding))
             (assoc x :sctp/ipv4 ip)))
   :ipv6 (fn [{:sctp/keys [param-length param-padding buf] :as x}]
           (let [ip (string/join ":"
                                 (->> (range)
                                      (take param-length)
                                      (map (fn [_] (.get buf)))
                                      (map (fn [e] (bit-and e 0xff)))
                                      (map (fn [x] (Integer/toHexString x)))
                                      (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
                                      (partition 2)
                                      (map (fn [[a b]] (str a b)))
                                      (doall)))]
             #_(run! (fn [_] (.get buf)) (range param-padding))
             (assoc x :sctp/ipv6 ip)))
   :cookie-ttl (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                 (let [cookie-ttl (-> buf (.getShort) (bit-and 0xffff))]
                   #_(run! (fn [_] (.get buf)) (range param-padding))
                   (assoc x :sctp/cookie-ttl cookie-ttl)))
   :cookie (fn [{:sctp/keys [param-length param-padding buf] :as x}]
             (let [cookie (->> (range)
                               (take param-length)
                               (map (fn [_] (.get buf)))
                               (map (fn [e] (bit-and e 0xff)))
                               (doall))]
               (run! (fn [_] (.get buf)) (range param-padding))
               (assoc x :sctp/cookie cookie)))
   :hostname (fn [{:sctp/keys [param-length param-padding buf] :as x}]
               (let [hostname (->> (range)
                                   (take param-length)
                                   (map (fn [_] (.get buf)))
                                   (remove (fn [e] (= e 0)))
                                   (map char)
                                   (apply str)
                                   (doall))]
                 (run! (fn [_] (.get buf)) (range param-padding))
                 (assoc x :sctp/hostname hostname)))
   :address-family (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                     (let [types (->> (range)
                                      (take (/ param-length 2))
                                      (map (fn [_] (.getShort buf)))
                                      (map (fn [e] (bit-and e 0xffff)))
                                      (map (fn [e] (get parameter-map e)))
                                      (doall))]
                       #_(run! (fn [_] (.get buf)) (range param-padding))
                       (assoc x :sctp/address-family types)))
   :forward-tsn (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                  (let []
                    (assoc x :sctp/forward-tsn :supported)))
   :extensions (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                 (let [types (->> (range)
                                  (take param-length)
                                  (map (fn [_] (.get buf)))
                                  (map (fn [e] (bit-and e 0xff)))
                                  (map (fn [e] (get chunk-map e e)))
                                  (into [])
                                  (doall))]
                   (run! (fn [_] (.get buf)) (->> param-padding (range)))
                   (assoc x :sctp/extensions types)))
   :random (fn [{:sctp/keys [param-length param-padding buf] :as x}]
             (let [random (->> (range)
                               (take param-length)
                               (map (fn [_] (.get buf)))
                               (map (fn [e] (bit-and e 0xff)))
                               (into [])
                               (doall))]
               (run! (fn [_] (.get buf)) (->> param-padding (range)))
               (assoc x :sctp/random random)))
   :hmac-algo (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                (let [hmac-algo (->> (range)
                                     (take (/ param-length 2))
                                     (map (fn [_] (.getShort buf)))
                                     (map (fn [e] (bit-and e 0xffff)))
                                     (map (fn [e] (get hmac-map e)))
                                     (into [])
                                     (doall))]
                  (run! (fn [_] (.get buf)) (->> param-padding (range)))
                  (assoc x :sctp/hmac-algo hmac-algo)))
   :chunks (fn [{:sctp/keys [chunk-padding param-length param-padding buf] :as x}]
             (let [chunks (->> (range)
                               (take param-length)
                               (map (fn [_] (.get buf)))
                               (map (fn [e] (bit-and e 0xff)))
                               (map (fn [e] (get chunk-map e e)))
                               (into [])
                               (doall))]
               (when (-> buf (.limit) (- (.position buf)) (> chunk-padding))
                 (run! (fn [_] (.get buf)) (->> param-padding (range))))
               (assoc x :sctp/authed-chunks chunks)))})

#_(
   (in-ns 'jaq.http.xrf.sctp)
   *e
   (->> [1 210 22] (map str))
   )


(defn decode-opt-params
  "        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Parameter Type       |       Parameter Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                       Parameter Value                         /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [buf] :as x}]
  (let [type (-> buf (.getShort) (bit-and 0xffff))
        length (-> buf (.getShort) (bit-and 0xffff))
        padding (-> length (mod -4) -)
        k (get parameter-map type :unknown)
        f (get decode-opt-map k)]
    (prn ::processing ::opt type k length padding buf)
    (->> (assoc x
                :sctp/param-type type
                :sctp/param-length (- length 4) ;; length includes type and length
                :sctp/param-padding padding)
         (f))))

(defn decode-params
  [{:sctp/keys [buf chunk-type chunk-length] :as x}]
  (let [k (get chunk-map chunk-type)
        f (get decode-chunk-map k)]
    (prn ::processing k chunk-length)
    (->> (assoc x :sctp/chunk k)
         (f))))


(def ^Charset utf8
  (Charset/forName "UTF-8"))

(defn decode-message
  "      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Message Type |  Channel Type |            Priority           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Reliability Parameter                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Label Length          |       Protocol Length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     |                             Label                             |
     /                                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                                                               /
     |                            Protocol                           |
     /                                                               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [buf] :as x}]
  (let [message-type (-> buf (.get) (bit-and 0xff))
        channel-type (-> buf (.get) (bit-and 0xff))
        priority (-> buf (.getShort) (bit-and 0xffff))
        reliability (-> buf (.getInt) (bit-and 0xffffffff))
        label-length (-> buf (.getShort) (bit-and 0xffff))
        protocol-length (-> buf (.getShort) (bit-and 0xffff))
        label (-> buf (.slice) (.limit label-length) (.rewind) (->> (.decode utf8) (.toString)))
        _ (-> buf (.position (+ label-length (.position buf))))
        protocol (->> (range)
                      (take protocol-length)
                      (map (fn [_] (.get buf)))
                      (map (fn [e] (bit-and e 0xff)))
                      (into [])
                      (doall))]
    (assoc x
           :sctp/message (get message-map message-type)
           :sctp/channel (get channel-map channel-type)
           :datachannel/priority priority
           :datachannel/reliability reliability
           :datachannel/label label
           :datachannel/label-length label-length
           :datachannel/protocol protocol)))

#_(

   (->> jaq.http.xrf.ice/y :context/packet (map (fn [x] (bit-and x 0xff))))
   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (byte-array) (ByteBuffer/wrap))]
     #_(->> (range) (take 12) (map (fn [_] (.get buf))) (doall))
     #_(-> buf (.duplicate) (.limit 4) (.rewind) (->> (.decode utf8) (.toString)))
     #_(-> buf (.duplicate) (.limit 4) (.rewind) )
     #_(->> (map (fn [_] (.get buf))) (map char) (apply str) (doall))
     #_buf
     (decode-message {:sctp/buf buf}))

   (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (drop 12) (map char) (apply str))

   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (drop 12) (byte-array) (ByteBuffer/wrap))]
     (-> buf (.duplicate) (.limit 4) (.rewind) (->> (.decode utf8) (.toString)))
     )

   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (byte-array) (ByteBuffer/wrap))]
     (.position buf 12)
     (-> buf (.slice) (.limit 4) (.rewind) (->> (.decode utf8) (.toString)))
     )

   )

#_(
   *e
   (def y jaq.http.xrf.ice/y)

   (->> y :context/vacc)
   (let [buf (->> y :context/vacc
                  (byte-array)
                  (ByteBuffer/wrap))
         x {:sctp/buf buf}]

     (->> x
          (decode-header)
          ;; 1st chunk
          (decode-chunk)
          (decode-params)
          (decode-opt-params)
          (decode-opt-params)
          (decode-opt-params)
          (decode-opt-params)
          (decode-opt-params)
          ;; end 1st chunk
          )
     )
   (into [] (comp
             (map (fn [x] {:byte x}))
             header-rf
             (drop 1)
             chunk-rf
             (drop 1)
             (rf/one-rf :sctp/chunk
                        (map (fn [{:sctp/keys [buf] :as x}]
                               (loop [x' (->> x (decode-params))]
                                 (prn buf)
                                 (if-not (.hasRemaining buf)
                                   x'
                                   (recur (decode-opt-params x')))))))
             padding-rf
             (drop 1)
             (take 1))
         (-> y :context/vacc))
   (-> (/ 86 4) double)

   (->> y :context/vacc (take (+ 12 86 2 2)))
   (->> y :context/vacc (drop 12) (drop 4) (take 84))
   (->> [19 136] (byte-array) (ByteBuffer/wrap) (.getShort))
   (+ 12 86 2)
   )



(def header-rf
  (fn [rf]
    (let [header-length 12
          val (volatile! nil)
          vacc (volatile! [])
          assoc-fn (fn [x]
                     (let [{:sctp/keys [src dst tag checksum]} @val]
                       (assoc x
                              :sctp/src src
                              :sctp/dst dst
                              :sctp/tag tag
                              :sctp/checksum checksum)))]
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
                      (assoc x :sctp/buf)
                      (decode-header)
                      (vreset! val))
                 (rf acc (assoc-fn x)))))

           :else
           (rf acc (assoc-fn x))))))))

(def chunk-rf
  (comp
   (fn [rf]
     (let [length 4
           val (volatile! nil)
           vacc (volatile! [])
           assoc-fn (fn [x]
                      (let [{:sctp/keys [chunk-type chunk-flags chunk-length chunk-padding]} @val]
                        (assoc x
                               :sctp/chunk-type chunk-type
                               :sctp/chunk-flags chunk-flags
                               :sctp/chunk-length chunk-length
                               :sctp/chunk-padding chunk-padding)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [byte] :as x}]
          (cond
            (< (count @vacc) length)
            (do
              (vswap! vacc conj byte)
              (if-not (= (count @vacc) length)
                acc
                (do
                  (->> @vacc
                       (byte-array)
                       (ByteBuffer/wrap)
                       (assoc x :sctp/buf)
                       (decode-chunk)
                       (vreset! val))
                  (rf acc (assoc-fn x)))))

            :else
            (rf acc (assoc-fn x)))))))
   (drop 1)
   (fn [rf]
     (let [val (volatile! nil)
           vacc (volatile! [])
           assoc-fn (fn [x]
                      (assoc x :sctp/buf @val
                             :context/vacc @vacc))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [byte]
                :sctp/keys [chunk-length chunk-padding]
                :as x}]
          (cond
            (< (count @vacc) chunk-length)
            (do
              (vswap! vacc conj byte)
              (if-not (= (count @vacc) chunk-length)
                acc
                (do
                  (->> @vacc
                       (byte-array)
                       (ByteBuffer/wrap)
                       (vreset! val))
                  (rf acc (assoc-fn x)))))

            :else
            (rf acc (assoc-fn x)))))))))

(def padding-rf
  (fn [rf]
    (let [cnt (volatile! 0)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:sctp/keys [chunk-padding] :as x}]
         (cond
           (< @cnt chunk-padding)
           (do
             (vswap! cnt inc)
             (if-not (= @cnt chunk-padding)
               acc
               (rf acc x)))

           :else
           (rf acc x)))))))

;; TODO: multiple chunks
(def sctp-rf
  (comp
   (fn [rf]
     (let [packet (volatile! [])]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [byte]
                :sctp/keys [chunk-padding] :as x}]
          (vswap! packet conj byte)
          (rf acc (assoc x :context/packet @packet))))))
   header-rf
   (drop 1)
   chunk-rf
   (drop 1)
   (rf/one-rf :sctp/chunk
              (map (fn [{:sctp/keys [buf] :as x}]
                     (loop [x' (->> x (decode-params))]
                       (prn buf)
                       (if-not (.hasRemaining buf)
                         x'
                         (recur (decode-opt-params x')))))))
   padding-rf))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.sctp)
   )

;; encoding
(def ^SecureRandom secure-random (SecureRandom.))
(defn random-int []
  (-> secure-random (.nextInt)))

#_(
   (-> (random-int) int)
   (-> secure-random (.nextInt))
   )

(defn opt-param! [buf type length val padding]
  (-> buf
      (.putShort (get parameters type))
      ;; include type and length
      (.putShort (+ length 4)))
  (when val
    (.put buf val))
  (when  padding
    (let [padding (-> length (mod -4) -)]
      (run! (fn [_] (.put buf (byte 0))) (range padding)))))

(def encode-map
  {:init-ack (fn [{:sctp/keys [buf chunk init-tag window outbound inbound cookie initial-tsn]
                   :as x}]
               (let [cookie (or cookie (-> (random-int) (biginteger) (.toByteArray)))]
                 ;; fixed params
                 (-> buf
                     (.putInt init-tag)
                     (.putInt window)
                     (.putShort outbound)
                     (.putShort inbound)
                     (.putInt initial-tsn))
                 ;; opt param
                 (opt-param! buf :cookie (count cookie) cookie true)
                 (opt-param! buf :forward-tsn 0 nil false)))
   :cookie-echo (fn [{:sctp/keys [buf cookie] :as x}]
                  (let [cookie (or cookie (-> (random-int) (biginteger) (.toByteArray)))]
                    ;; fixed params
                    (-> buf (.put cookie))))
   :cookie-ack (fn [{:sctp/keys [buf chunk] :as x}]
                 (let []
                   buf))})

(defn encode-chunk
  "        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                          Chunk Value                          /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [buf chunk chunk-flags]
    :as x}]
  (let [chunk-flags (or chunk-flags 0)]
    (prn ::chunk (get chunks chunk) chunk chunk-flags)
    (-> buf
        (.put (-> (get chunks chunk) (byte)))
        (.put (byte chunk-flags))
        (.mark)
        ;; dummy length
        (.putShort 0))
    x))

#_(
   (encode-chunk {})

   (let [{:sctp/keys [buf chunk chunk-flags]
          :or {chunk-flags 0}
          :as x} {}]
     chunk-flags)
   )

(defn encode
  "        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Source Port Number        |     Destination Port Number   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Verification Tag                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Checksum                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  [{:sctp/keys [src dst tag chunks buf] :as x}]
  ;; header
  (-> buf
      (.putShort src)
      (.putShort dst)
      (.putInt tag)
      ;; remember
      (.mark)
      ;; fill in checksum at the end
      (.putInt 0))
  (doseq [{:keys [chunk chunk-flags params]} chunks]
    (let [pos (.position buf)
          bb (.duplicate buf)]
      (prn ::encoding chunk)
      (->> (assoc x
                  :sctp/buf bb
                  :sctp/chunk-flags chunk-flags
                  :sctp/chunk chunk :sctp/params params)
           (encode-chunk)
           (conj [])
           (apply (get encode-map chunk)))
      (let [length (-> (.position bb) (- pos))
            padding (-> length (mod -4) -)]
        ;; add chunk length
        (-> bb
            (.reset)
            (.putShort length))
        ;; forward buf
        (prn ::padding padding pos length buf bb)
        (->> (+ pos length)
             (.position buf))
        ;; add chunk padding
        (run! (fn [_] (.put buf (byte 0))) (range padding)))))
  (let [crc32c (CRC32C.)
        end (.position buf)]
    ;; calculate checksum
    (.update crc32c (-> buf (.duplicate) (.flip)))
    (-> buf
        (.reset)
        (.order ByteOrder/LITTLE_ENDIAN)
        (.putInt (-> crc32c (.getValue)))
        (.order ByteOrder/BIG_ENDIAN)
        (.position end)
        (.flip))))

#_(

   (in-ns 'jaq.http.xrf.sctp)

   ;; crc32c debugging
   (->> jaq.http.xrf.ice/y :context/packet (map (fn [x] (bit-and x 0xff))))
   ;; 1744600416
   (def b [19 136 19 136 0 0 0 0 0 0 0 0 1 0 0 86 101 10 120 33 0 2 0 0 4 0 8 0 74 222 36 161 192 0 0 4 128 8 0 9 192 15 193 128 130 0 0 0 128 2 0 36 28 71 10 84 123 238 211 123 100 197 217 81 197 253 62 97 20 43 247 11 115 123 68 17 90 62 150 66 197 130 3 10 128 4 0 6 0 1 0 0 128 3 0 6 128 193 0 0])
   (def a *1)
   (def b (concat (take 8 a) [0 0 0 0] (->> a (drop 12))))
   (let [crc32c (CRC32C.)
         buf (->> b (byte-array))]
     (.update crc32c buf)
     (-> crc32c (.getValue))
     )
   (->> b (string/join ", "))

   (let [buf (-> [59 96 207 217] (reverse) (byte-array) (ByteBuffer/wrap) #_(.order ByteOrder/LITTLE_ENDIAN))]
     (bit-and 0xffffffff (.getInt buf)))

   (let [buf (ByteBuffer/allocate 100)]
     (-> buf
         (.putShort 0x0102)
         (.order ByteOrder/LITTLE_ENDIAN)
         (.putShort 0x0102)
         (.order ByteOrder/BIG_ENDIAN)
         (.putInt 0xff)
         (.flip))
     (->> (range) (take (.limit buf)) (map (fn [_] (bit-and 0xff (.get buf))))))
   *e
   )

#_(

   (->> jaq.http.xrf.ice/y :sctp/chunk (filter (fn [[k v]] (and
                                                #_(not= k :sctp/chunk)
                                                (= (namespace k) "sctp")))) (into {}))
   )
#_(

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         cookie (-> (random-int) (biginteger) (.toByteArray))]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000
              :sctp/tag tag
              :sctp/chunks [{:chunk :cookie-ack}]})
     (->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         cookie (-> (random-int) (biginteger) (.toByteArray))]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000
              :sctp/tag tag
              :sctp/chunks [{:chunk :cookie-echo}]})
     (->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         init-tag (random-int)
         window 1500
         outbound 1024
         inbound 1024
         cookie (-> (random-int) (biginteger) (.toByteArray))
         initial-tsn (random-int)]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000
              :sctp/tag tag
              :sctp/init-tag init-tag :sctp/window window
              :sctp/outbound outbound :sctp/inbound inbound
              :sctp/cookie cookie :sctp/initial-tsn initial-tsn
              :sctp/chunks [{:chunk :init-ack}]})
     (->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         init-tag (random-int)
         window 1500
         outbound 1024
         inbound 1024
         cookie (-> (random-int) (biginteger) (.toByteArray))
         initial-tsn (random-int)]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000
              :sctp/tag tag
              :sctp/init-tag init-tag :sctp/window window
              :sctp/outbound outbound :sctp/inbound inbound
              :sctp/cookie cookie :sctp/initial-tsn initial-tsn
              :sctp/chunks [{:chunk :init-ack}]})
     (into []
           (comp
            header-rf
            (drop 1)
            chunk-rf
            #_(drop 1)
            (map (fn [{:sctp/keys [buf] :as x}]
                   (loop [x' (->> x (decode-params))]
                     (prn buf)
                     (if-not (.hasRemaining buf)
                       x'
                       (recur (decode-opt-params x')))))))
           (->> (range)
                (take (.limit buf))
                (map (fn [_] (-> (.get buf) (bit-and 0xff))))
                (map (fn [x] {:byte x}))))
     )

   *e
   )

#_(
   (in-ns 'jaq.http.xrf.sctp)
   (require 'jaq.http.xrf.sctp :reload)
   *e

   ;; dtls client
   (let [;;host "localhost"
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
                 (nio/datagram-channel-rf
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
                   (rf/debug-rf ::handshake)
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
                   #_(comp
                      nio/writable-rf
                      (dtls/request-ssl-rf (comp
                                            #_(rf/debug-rf ::sent)
                                            (map
                                             (fn [{:http/keys [host port] :as x}]
                                               (assoc x :http/req req)))))
                      (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                    (.hasRemaining (block)))))
                   #_nio/close-connection))))
               #_nio/close-rf)))]
     (let [port 2223
           host "192.168.1.140"]
       (->> [{:context/bip-size (* 20 4096)
              :ssl/packet-size 1024
              :ssl/certs [cert]
              :ssl/mode :server
              :http/host host
              :http/port port
              :http/local-port port}]
            (into [] xf))))
   (def x (first *1))
   *e
   *ns*
   (require 'jaq.http.xrf.sctp)
   (in-ns 'jaq.http.xrf.sctp)
   (ns-unmap *ns* 'y)
   (->> y :ssl/engine (.getSSLContext))
   (->> y :byte)

   (def cert (dtls/self-cert :cert/alias "server"))
   ;; fingerprint
   (->> cert :cert/cert (.getEncoded)
        (.digest (java.security.MessageDigest/getInstance "SHA-256"))
        (map (fn [x] (bit-and x 0xff)))
        (map (fn [x] (Integer/toHexString x)))
        (map (fn [x] (if (= (count x) 1) (str "0" x) x)))
        (map string/upper-case)
        (into []))

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
