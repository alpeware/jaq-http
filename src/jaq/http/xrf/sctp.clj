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
   :heartbeat-ack 5
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
  {:heartbeat 1
   :ipv4 5
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
   :webrtc/binary 53
   :webrtc/empty-string 56
   :webrtc/empty-binary 57})

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
    (prn ::chunk chunk-type chunk-flags chunk-length chunk-padding)
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
                 protocol (-> buf (.getInt) (bit-and 0xffffffff))
                 data (->> (range)
                           (take (- chunk-length 12))
                           (map (fn [_] (.get buf)))
                           (map (fn [e] (bit-and e 0xff)))
                           (doall))]
             #_(run! (fn [_] (.get buf)) (range chunk-padding))
             (assoc x
                    :sctp/data-flags flags
                    :sctp/tsn tsn :sctp/stream stream
                    :sctp/sequence sequence :sctp/protocol (get protocol-map protocol)
                    :sctp/data data)))
   :sack (fn [{:sctp/keys [buf tsn] :as x}]
           (let [tsn-ack (-> (.getInt buf) (bit-and 0xffffffff))
                 window (-> (.getInt buf) (bit-and 0xffffffff))
                 gap-blocks (-> buf (.getShort) (bit-and 0xffff))
                 tsn-dups (-> buf (.getShort) (bit-and 0xffff))
                 gaps (->> (range)
                           (take (* gap-blocks 2))
                           (map (fn [_] (.getShort buf)))
                           (map (fn [e] (bit-and e 0xffff)))
                           #_(map (fn [e] (+ e tsn-ack)))
                           (partition 2)
                           ;; TODO: need the complement between tsn and tsn-ack to get gaps
                           #_(mapcat (fn [[start end]]
                                       (-> start (inc) (range end))))
                           (into [])
                           (doall))
                 dups (->> (range)
                           (take tsn-dups)
                           (map (fn [_] (.getInt buf)))
                           (map (fn [e] (bit-and e 0xffffffff)))
                           (doall))]
             (assoc x
                    :sctp/tsn-ack tsn-ack :sctp/window window
                    :sctp/gaps gaps
                    :sctp/dups dups)))
   :heartbeat (fn [{:sctp/keys [buf chunk-length] :as x}]
                (let []
                  x))})

#_(
   (in-ns 'jaq.http.xrf.sctp)
   *e
   *ns*

   (range 2 4)

   (->> {:unordered false :begining false :ending true}
        (remove (fn [[k v]] (false? v)))
        (map (fn [[k v]] k))
        (set))

   )

(def decode-opt-map
  {:heartbeat (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                (let [heartbeat (->> (range)
                                     (take param-length)
                                     (map (fn [_] (.get buf)))
                                     (map (fn [e] (bit-and e 0xff)))
                                     (doall))]
                  (run! (fn [_] (.get buf)) (range param-padding))
                  (assoc x :sctp/heartbeat heartbeat)))
   :ipv4 (fn [{:sctp/keys [param-length param-padding buf] :as x}]
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

(def decode-message-map
  {:message/ack (fn [{:sctp/keys [buf] :as x}]
                  x)
   :message/open (fn [{:sctp/keys [buf] :as x}]
                   (let [channel-type (-> buf (.get) (bit-and 0xff))
                         priority (-> buf (.getShort) (bit-and 0xffff))
                         reliability (-> buf (.getInt) (bit-and 0xffffffff))
                         label-length (-> buf (.getShort) (bit-and 0xffff))
                         protocol-length (-> buf (.getShort) (bit-and 0xffff))
                         label (-> buf (.slice) (.limit label-length) (.rewind) (->> (.decode utf8) (.toString)))
                         _ (-> buf (.position (+ label-length (.position buf))))
                         ;; TODO: is this used for anything?
                         protocol (->> (range)
                                       (take protocol-length)
                                       (map (fn [_] (.get buf)))
                                       (map (fn [e] (bit-and e 0xff)))
                                       (into [])
                                       (doall))]
                     (assoc x
                            :sctp/channel (get channel-map channel-type)
                            :datachannel/priority priority
                            :datachannel/reliability reliability
                            :datachannel/label label
                            :datachannel/label-length label-length
                            :datachannel/protocol protocol)))})

(def decode-protocol-map
  {:webrtc/dcep (fn [{:sctp/keys [buf] :as x}]
                  (let [type (-> buf (.get) (bit-and 0xff))
                        k (get message-map type :unknown)
                        f (get decode-message-map k)]
                    (prn ::processing ::message type k)
                    (->> (assoc x
                                :datachannel/message-type type
                                :datachannel/message k)
                         (f))))
   :webrtc/string (fn [{:sctp/keys [buf] :as x}]
                    (let [payload (->> buf (.decode utf8) (.toString))]
                      (assoc x :datachannel/payload payload)))
   :webrtc/string-empty (fn [{:sctp/keys [buf] :as x}]
                          (let []
                            (assoc x :datachannel/payload "")))
   :webrtc/binary (fn [{:sctp/keys [buf] :as x}]
                    (let [payload (loop [acc []]
                                    (if-not (.hasRemaining buf)
                                      acc
                                      (recur (conj acc (-> buf (.get) (bit-and 0xff))))))]
                      (assoc x :datachannel/payload payload)))
   :webrtc/binary-empty (fn [{:sctp/keys [buf] :as x}]
                          (let []
                            (assoc x :datachannel/payload nil)))})

#_(

   )

(defn decode-message [{:sctp/keys [data protocol] :as x}]
  (let [buf (->> data (byte-array) (ByteBuffer/wrap))
        f (get decode-protocol-map protocol)]
    (->> (assoc x :sctp/buf buf)
         (f))))

#_(

   (let [protocol (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/protocol)
         data (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data)]
     (->> {:sctp/protocol (get protocol-map protocol)
           :sctp/data data}
          (decode-message))
     )

   (->> jaq.http.xrf.ice/y :context/packet (map (fn [x] (bit-and x 0xff))))
   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (byte-array) (ByteBuffer/wrap))]
     (decode-protocol {:sctp/buf buf}))

   (->> jaq.http.xrf.ice/y :sctp/chunk (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {}))

   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (drop 12) (byte-array) (ByteBuffer/wrap))]
     (-> buf (.duplicate) (.limit 4) (.rewind) (->> (.decode utf8) (.toString)))
     )

   (let [buf (->> jaq.http.xrf.ice/y :sctp/chunk :sctp/data (byte-array) (ByteBuffer/wrap))]
     (loop [acc []]
       (if-not (.hasRemaining buf)
         acc
         (recur (conj acc (-> buf (.get) (bit-and 0xff))))))
     )

   )

#_(
   *e
   (def y jaq.http.xrf.ice/y)

   (->> y :context/vacc)
   (let [buf (->> y :context/packet
                  (byte-array)
                  (ByteBuffer/wrap))
         x {:sctp/buf buf}]

     (->> x
          (decode-header)
          ;; 1st chunk
          (decode-chunk)
          (decode-params)
          ;; end 1st chunk
          (decode-chunk)
          (decode-params)
          #_(decode-opt-params)
          ))

   (into [] (comp
             (map (fn [x] {:byte x}))
             header-rf
             (drop 1)
             chunks-rf
             (take 1))
         (-> y :context/packet))

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
                  #_(prn ::chunk ::header @val)
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
                  (prn ::chunked)
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
        ([acc {:keys [byte]
               :sctp/keys [chunk-padding] :as x}]
         (prn ::byte byte)
         (cond
           (< @cnt chunk-padding)
           (do
             (vswap! cnt inc)
             (if-not (= @cnt chunk-padding)
               acc
               (rf acc x)))

           :else
           (rf acc x)))))))

(def chunks-rf
  (fn [rf]
    (let [chunks (volatile! [])
          done (volatile! false)
          xf (rf/repeatedly-rf (comp chunk-rf
                                     #_(drop 1)
                                     (rf/one-rf :sctp/chunk
                                                (comp
                                                 (map (fn [{:context/keys [remaining]
                                                            :sctp/keys [chunk-padding]
                                                            :as x}]
                                                        (prn ::processed ::chunk remaining chunk-padding)
                                                        x))
                                                 (map (fn [{:sctp/keys [buf] :as x}]
                                                        (loop [x' (->> x (decode-params))]
                                                          (prn buf)
                                                          (if-not (.hasRemaining buf)
                                                            x'
                                                            (recur (decode-opt-params x'))))))
                                                 (map (fn [{:sctp/keys [chunk] :as x}]
                                                        (if (= chunk :data)
                                                          (decode-message x)
                                                          x)))))
                                     padding-rf
                                     (map (fn [{:context/keys [remaining]
                                                :sctp/keys [chunk-padding]
                                                :as x}]
                                            (prn ::done ::chunk remaining chunk-padding)
                                            (vswap! chunks conj x)
                                            x))))
          xrf (xf (rf/result-fn))
          assoc-fn (fn [x]
                     (assoc x :sctp/chunks @chunks))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [byte]
               :context/keys [remaining]
               :as x}]
         (if @done
           (->> (assoc-fn x)
                (rf acc))
           (do
             (xrf acc x)
             (if (= 0 remaining)
               (do
                 (prn ::done ::chunks remaining)
                 (vreset! done true)
                 (->> (assoc-fn x)
                      (rf acc)))
               acc))))))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.sctp)

   (def y jaq.http.xrf.ice/y)

   (->> jaq.http.xrf.ice/y :context/packet (map (fn [x] (bit-and x 0xff))))
   (->> (interleave
         (->> y :context/packet (count) (range) (reverse))
         (->> y :context/packet))
        (into [] (comp
                  (partition-all 2)
                  (map (fn [[y x]] {:byte x :context/remaining y}))
                  header-rf
                  (drop 1)
                  chunks-rf))
        (first)
        :sctp/chunks
        (map :sctp/chunk)
        #_(map (fn [{:sctp/keys [chunk]}] chunk))
        (filter (fn [{:datachannel/keys [message]}] (= message :message/open)))
        (map :sctp/protocol)
        #_(first))
   )


#_(defn chunks-rf [xf]
    (fn [rf]
      (let [xrf (xf (result-fn))]
        (fn
          ([] (rf))
          ([acc] (rf acc))
          ([acc {:keys [byte]
                 :sctp/keys [chunk-padding] :as x}]
           (vswap! packet conj byte)
           (rf acc (assoc x :context/packet @packet)))))))

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
   chunks-rf
   #_(comp
      chunk-rf
      (drop 1)
      (rf/one-rf :sctp/chunk
                 (comp
                  (map (fn [{:context/keys [remaining] :as x}]
                         (prn ::processed ::chunk remaining)
                         x))
                  (map (fn [{:sctp/keys [buf] :as x}]
                         (loop [x' (->> x (decode-params))]
                           (prn buf)
                           (if-not (.hasRemaining buf)
                             x'
                             (recur (decode-opt-params x'))))))))
      padding-rf)))

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

(def encode-message-map
  {:message/open (fn [{:sctp/keys [buf channel]
                       :datachannel/keys [priority reliability label protocol]
                       :as x}]
                   (let [label-length (count label)
                         protocol-length (count protocol)]
                     (def y x)
                     (prn ::message ::open)
                     (-> buf
                         (.put (->> channel (get channels) (byte)))
                         (.putShort priority)
                         (.putInt reliability)
                         (.putShort label-length)
                         (.putShort protocol-length)
                         (.put (->> label (.getBytes)))
                         (.put (->> protocol (byte-array))))))
   :message/ack (fn [{:sctp/keys [buf]}]
                  buf)})

#_(
   (-> (get encode-message-map :message/open) (apply [y]))
   (-> y :datachannel/priority)
   *e

   (get channels :datachannel/reliable)
   (let [buf (ByteBuffer/allocate 10)
         s "foo"
         p [0 1 2 3]]
     #_(->> s (.getBytes) (.put buf))
     (->> p (byte-array) (.put buf)))
   (get messages :message/ack)
   )

(def encode-protocol-map
  {:webrtc/dcep (fn [{:sctp/keys [buf]
                      :datachannel/keys [message]
                      :as x}]
                  (let [f (get encode-message-map message)
                        type (get messages message)]
                    (prn ::processing ::message type)
                    (-> buf
                        (.put (byte type)))
                    (->> x (f))))
   :webrtc/string (fn [{:sctp/keys [buf]
                        :datachannel/keys [payload]
                        :as x}]
                    (-> buf (.put (.getBytes payload))))
   :webrtc/string-empty (fn [{:sctp/keys [buf]
                              :datachannel/keys [payload]
                              :as x}]
                          buf)
   :webrtc/binary (fn [{:sctp/keys [buf]
                        :datachannel/keys [payload]
                        :as x}]
                    (-> buf (.put payload)))
   :webrtc/binary-empty (fn [{:sctp/keys [buf] :as x}]
                          buf)})

#_(
   (in-ns 'jaq.http.xrf.sctp)
   (get messages :message/open)
   (->> jaq.http.xrf.ice/y
        (filter (fn [[k v]] (and
                             #_(not= k :sctp/chunk)
                             (contains? #{"sctp" "datachannel"} (namespace k)))))
        (into {}))
   )

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
                   buf))
   :data (fn [{:sctp/keys [buf tsn stream sequence protocol]
               :as x}]
           (let [start (-> buf (.position) (+ 4 2 2 4))
                 f (get encode-protocol-map protocol)]
             (-> buf
                 (.putInt tsn)
                 (.putShort stream)
                 (.putShort sequence)
                 (.putInt (get protocols protocol)))
             ;; encode payload
             (f x)
             #_(let [padding (-> buf (.position) (- start) (mod -4) -)]
               (prn ::data ::padding padding)
               (run! (fn [_] (.put buf (byte 0))) (range padding)))))
   ;; TODO: send SACK for received message
   ;; TODO: process multiple incoming chunks
   :sack (fn [{:sctp/keys [buf tsn tsn-ack window gaps dups]
               :as x}]
           (let [gap-blocks (count gaps)
                 tsn-dups (count dups)]
             (-> buf
                 (.putInt tsn-ack)
                 (.putInt window)
                 (.putShort gap-blocks)
                 (.putShort tsn-dups))
             ;; gap blocks
             (doseq [[start end] gaps]
               (-> buf
                   (.putShort start)
                   (.putShort end)))
             ;; tsn dups
             (doseq [dup dups]
               (.putInt buf dup))))
   :heartbeat-ack (fn [{:sctp/keys [buf heartbeat] :as x}]
                    (let [length (count heartbeat)
                          val (->> heartbeat (byte-array))]
                      (opt-param! buf :heartbeat length val false)))})

#_(
   *ns*
   (in-ns 'jaq.http.xrf.sctp)
   ;; gap blocks: report on tsns received relative to tsn ack
   ;; so really the complement of the missing ones
   ;; TODO: figure out a better way to handle

   )

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
  (prn ::chunk (get chunks chunk) chunk chunk-flags)
  (-> buf
      (.put (-> (get chunks chunk) (byte)))
      (.put (byte chunk-flags))
      (.mark)
      ;; dummy length
      (.putShort 0))
  x)

#_(
   (in-ns 'jaq.http.xrf.sctp)

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
  (doseq [{:keys [chunk chunk-flags]} chunks]
    (let [pos (.position buf)
          bb (.duplicate buf)]
      (prn ::encoding chunk chunk-flags)
      (->> (assoc x
                  :sctp/buf bb
                  :sctp/chunk-flags chunk-flags
                  :sctp/chunk chunk)
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

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         cookie (-> (random-int) (biginteger) (.toByteArray))]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000
              :sctp/tag tag
              :sctp/chunks [{:chunk :cookie-ack :chunk-flags 0}]})
     (->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

   (let [buf (ByteBuffer/allocate 1500)
         tag (random-int)
         cookie (-> (random-int) (biginteger) (.toByteArray))]
     (encode {:sctp/buf buf :sctp/src 5000 :sctp/dst 5000 :sctp/tag tag
              :sctp/heartbeat (range 10)
              :sctp/chunks [{:chunk :heartbeat-ack :chunk-flags 0}]})
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
         x (->> jaq.http.xrf.ice/y
                (filter (fn [[k v]] (and
                                     (not= k :sctp/buf)
                                     (contains? #{"sctp" "datachannel"} (namespace k)))))
                (into {}))]
     (->> (assoc x
                 :datachannel/message :message/ack #_(:sctp/message x)
                 :sctp/buf buf
                 :sctp/chunks [{:chunk :data :chunk-flags 3}])
          (encode))
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
                       (recur (decode-opt-params x'))))))
            (map (fn [{:sctp/keys [chunk] :as x}]
                   (merge x (->> x (decode-message))))))
           (->> (range)
                (take (.limit buf))
                (map (fn [_] (-> (.get buf) (bit-and 0xff))))
                (map (fn [x] {:byte x}))))
     #_(->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

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
              :sctp/tsn-ack tag
              :sctp/gaps [[2 3] [5 6]] :sctp/dups [init-tag tag]
              :sctp/chunks [{:chunk :sack :chunk-flags 0}{:chunk :init-ack :chunk-flags 0}]})
     #_(into []
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
