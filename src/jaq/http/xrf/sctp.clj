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
   [java.nio ByteBuffer]
   [java.security SecureRandom]
   [java.util.zip CRC32C]))

;; crc-c
;; TODO: remove if JDK version works
#_(def crc-c
    [0x00000000 0xF26B8303 0xE13B70F7 0x1350F3F4
     0xC79A971F 0x35F1141C 0x26A1E7E8 0xD4CA64EB
     0x8AD958CF 0x78B2DBCC 0x6BE22838 0x9989AB3B
     0x4D43CFD0 0xBF284CD3 0xAC78BF27 0x5E133C24
     0x105EC76F 0xE235446C 0xF165B798 0x030E349B
     0xD7C45070 0x25AFD373 0x36FF2087 0xC494A384
     0x9A879FA0 0x68EC1CA3 0x7BBCEF57 0x89D76C54
     0x5D1D08BF 0xAF768BBC 0xBC267848 0x4E4DFB4B
     0x20BD8EDE 0xD2D60DDD 0xC186FE29 0x33ED7D2A
     0xE72719C1 0x154C9AC2 0x061C6936 0xF477EA35
     0xAA64D611 0x580F5512 0x4B5FA6E6 0xB93425E5
     0x6DFE410E 0x9F95C20D 0x8CC531F9 0x7EAEB2FA
     0x30E349B1 0xC288CAB2 0xD1D83946 0x23B3BA45
     0xF779DEAE 0x05125DAD 0x1642AE59 0xE4292D5A
     0xBA3A117E 0x4851927D 0x5B016189 0xA96AE28A
     0x7DA08661 0x8FCB0562 0x9C9BF696 0x6EF07595
     0x417B1DBC 0xB3109EBF 0xA0406D4B 0x522BEE48
     0x86E18AA3 0x748A09A0 0x67DAFA54 0x95B17957
     0xCBA24573 0x39C9C670 0x2A993584 0xD8F2B687
     0x0C38D26C 0xFE53516F 0xED03A29B 0x1F682198
     0x5125DAD3 0xA34E59D0 0xB01EAA24 0x42752927
     0x96BF4DCC 0x64D4CECF 0x77843D3B 0x85EFBE38
     0xDBFC821C 0x2997011F 0x3AC7F2EB 0xC8AC71E8
     0x1C661503 0xEE0D9600 0xFD5D65F4 0x0F36E6F7
     0x61C69362 0x93AD1061 0x80FDE395 0x72966096
     0xA65C047D 0x5437877E 0x4767748A 0xB50CF789
     0xEB1FCBAD 0x197448AE 0x0A24BB5A 0xF84F3859
     0x2C855CB2 0xDEEEDFB1 0xCDBE2C45 0x3FD5AF46
     0x7198540D 0x83F3D70E 0x90A324FA 0x62C8A7F9
     0xB602C312 0x44694011 0x5739B3E5 0xA55230E6
     0xFB410CC2 0x092A8FC1 0x1A7A7C35 0xE811FF36
     0x3CDB9BDD 0xCEB018DE 0xDDE0EB2A 0x2F8B6829
     0x82F63B78 0x709DB87B 0x63CD4B8F 0x91A6C88C
     0x456CAC67 0xB7072F64 0xA457DC90 0x563C5F93
     0x082F63B7 0xFA44E0B4 0xE9141340 0x1B7F9043
     0xCFB5F4A8 0x3DDE77AB 0x2E8E845F 0xDCE5075C
     0x92A8FC17 0x60C37F14 0x73938CE0 0x81F80FE3
     0x55326B08 0xA759E80B 0xB4091BFF 0x466298FC
     0x1871A4D8 0xEA1A27DB 0xF94AD42F 0x0B21572C
     0xDFEB33C7 0x2D80B0C4 0x3ED04330 0xCCBBC033
     0xA24BB5A6 0x502036A5 0x4370C551 0xB11B4652
     0x65D122B9 0x97BAA1BA 0x84EA524E 0x7681D14D
     0x2892ED69 0xDAF96E6A 0xC9A99D9E 0x3BC21E9D
     0xEF087A76 0x1D63F975 0x0E330A81 0xFC588982
     0xB21572C9 0x407EF1CA 0x532E023E 0xA145813D
     0x758FE5D6 0x87E466D5 0x94B49521 0x66DF1622
     0x38CC2A06 0xCAA7A905 0xD9F75AF1 0x2B9CD9F2
     0xFF56BD19 0x0D3D3E1A 0x1E6DCDEE 0xEC064EED
     0xC38D26C4 0x31E6A5C7 0x22B65633 0xD0DDD530
     0x0417B1DB 0xF67C32D8 0xE52CC12C 0x1747422F
     0x49547E0B 0xBB3FFD08 0xA86F0EFC 0x5A048DFF
     0x8ECEE914 0x7CA56A17 0x6FF599E3 0x9D9E1AE0
     0xD3D3E1AB 0x21B862A8 0x32E8915C 0xC083125F
     0x144976B4 0xE622F5B7 0xF5720643 0x07198540
     0x590AB964 0xAB613A67 0xB831C993 0x4A5A4A90
     0x9E902E7B 0x6CFBAD78 0x7FAB5E8C 0x8DC0DD8F
     0xE330A81A 0x115B2B19 0x020BD8ED 0xF0605BEE
     0x24AA3F05 0xD6C1BC06 0xC5914FF2 0x37FACCF1
     0x69E9F0D5 0x9B8273D6 0x88D28022 0x7AB90321
     0xAE7367CA 0x5C18E4C9 0x4F48173D 0xBD23943E
     0xF36E6F75 0x0105EC76 0x12551F82 0xE03E9C81
     0x34F4F86A 0xC69F7B69 0xD5CF889D 0x27A40B9E
     0x79B737BA 0x8BDCB4B9 0x988C474D 0x6AE7C44E
     0xBE2DA0A5 0x4C4623A6 0x5F16D052 0xAD7D5351])

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
        checksum (-> (.getInt buf) (bit-and 0xffffffff))]
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
  {:init (fn [{:sctp/keys [param-length param-padding buf] :as x}]
           (let [init-tag (-> (.getInt buf) (bit-and 0xffffffff))
                 window (-> (.getInt buf) (bit-and 0xffffffff))
                 outbound (-> buf (.getShort) (bit-and 0xffff))
                 inbound (-> buf (.getShort) (bit-and 0xffff))
                 initial-tsn (-> (.getInt buf) (bit-and 0xffffffff))]
             ;; :init/tag init-tag :init/window window :init/outbound outbound :init/inbound inbound
             (assoc x
                    :sctp/init-tag init-tag :sctp/window window
                    :sctp/outbound outbound :sctp/inbound inbound
                    :sctp/initial-tsn initial-tsn)))})

(def decode-opt-map
  {:ipv4 (fn [{:sctp/keys [param-length param-padding buf] :as x}]
           (let [ip (string/join "."
                                 (->> (range)
                                      (take param-length)
                                      (map (fn [_] (.get buf)))
                                      (map (fn [e] (bit-and e 0xff)))
                                      (map str)))]
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
                                      (map (fn [[a b]] (str a b)))))]
             #_(run! (fn [_] (.get buf)) (range param-padding))
             (assoc x :sctp/ipv6 ip)))
   :cookie-ttl (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                 (let [cookie-ttl (-> buf (.getShort) (bit-and 0xffff))]
                   #_(run! (fn [_] (.get buf)) (range param-padding))
                   (assoc x :sctp/cookie-ttl cookie-ttl)))
   :hostname (fn [{:sctp/keys [param-length param-padding buf] :as x}]
               (let [hostname (->> (range)
                                   (take param-length)
                                   (map (fn [_] (.get buf)))
                                   (remove (fn [e] (= e 0)))
                                   (map char)
                                   (apply str))]
                 (run! (fn [_] (.get buf)) (range param-padding))
                 (assoc x :sctp/hostname hostname)))
   :address-family (fn [{:sctp/keys [param-length param-padding buf] :as x}]
                     (let [types (->> (range)
                                      (take (/ param-length 2))
                                      (map (fn [_] (.getShort buf)))
                                      (map (fn [e] (bit-and e 0xffff)))
                                      (map (fn [e] (get parameter-map e))))]
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
    (prn ::processing type k length padding)
    (->> (assoc x
                :sctp/param-type type
                :sctp/param-length (- length 4) ;; length includes type and length
                :sctp/param-padding padding)
         (f))))

(defn decode-params
  [{:sctp/keys [buf chunk-type chunk-length] :as x}]
  (let [k (get chunk-map chunk-type)
        f (get decode-chunk-map k)]
    (prn ::processing k chunk-length f)
    (->> (assoc x :sctp/chunk k)
         (f))))

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
                 (opt-param! buf :forward-tsn 0 nil false)))})

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
  ;; TODO: add checksum
  (let [crc32c (CRC32C.)
        end (.position buf)]
    ;; calculate checksum
    (.update crc32c (-> buf (.duplicate) (.flip)))
    (-> buf
        (.reset)
        (.putInt (-> crc32c (.getValue)))
        (.position end)
        (.flip))))

#_(
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
     #_(->> (range) (take (.limit buf)) (map (fn [_] (-> (.get buf) (bit-and 0xff))))))

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
