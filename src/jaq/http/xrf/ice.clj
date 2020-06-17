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
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.stun :as stun]
   [jaq.http.xrf.sctp :as sctp])
  (:import
   [java.net NetworkInterface]
   [java.nio ByteBuffer]))

(defn ips []
  (let [ip (fn [v]
              (cond
                (= (count v) 4)
                (string/join "."
                             (->> v
                                  (map (fn [e] (bit-and e 0xff)))
                                  (map str)))
                (= (count v) 16)
                (string/join ":"
                             (->> v
                                  (map (fn [e] (bit-and e 0xff)))
                                  (map (fn [x] (Integer/toHexString x)))
                                  (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
                                  (partition 2)
                                  (map (fn [[a b]] (str a b)))))))]
     (->> (NetworkInterface/getNetworkInterfaces)
          (enumeration-seq)
          (mapcat (fn [e]
                    (->> (.getInetAddresses e)
                         (enumeration-seq)
                         (remove (fn [f] (.isLoopbackAddress f)))
                         (map (fn [f] (->> (.getAddress f) (map (fn [x] (bit-and 0xff x))) ip))))))
          (set))))

(def receive-stun-rf
  (comp
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
                       (stun/decode)
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
                             (stun/decode-attributes))]
                (if-not (.hasRemaining buf)
                  x'
                  (recur (stun/decode-attributes x'))))
              x))))
   (map (fn [{:stun/keys [port ip message length cookie id] :as x}]
          (prn ::stun message length cookie id)
          x))
   (take 1)))

(defn data-channel-rf [xf]
  (comp
   (nio/datagram-channel-rf
    (comp
     nio/datagram-read-rf
     (map (fn [{:nio/keys [address] :as x}]
            (if address
              (assoc x
                     :http/host (-> address (.getAddress) (.getHostAddress))
                     :http/port (.getPort address))
              x)))
     nio/datagram-write-rf
     xf)
    #_(rf/catch-rf
       Exception
       (fn [{:error/keys [exception]
             :nio/keys [selection-key]
             :as x}]
         (prn ::error (.getMessage exception))
         (-> selection-key (.channel) (.close))
         (.cancel selection-key)
         (assoc x :http/json {:error (.getMessage exception)}))
       (comp
        nio/datagram-read-rf
        (map (fn [{:nio/keys [address] :as x}]
               (if address
                 (assoc x
                        :http/host (-> address (.getAddress) (.getHostAddress))
                        :http/port (.getPort address))
                 x)))
        nio/datagram-write-rf
        xf)))))

#_(
   (in-ns 'jaq.http.xrf.ice)
   )

(def simple-stun-rf
  "Parse and respond to a STUN binding request.

  This is useful when the UDP port is open without requiring hole punching."
  (comp
   ;; TODO: refactor scratch buffer for outgoing
   #_(rf/one-rf :context/buf (comp
                              (map (fn [x]
                                     (assoc x :context/buf (ByteBuffer/allocate 150))))
                              (map :context/buf)))
   ;; wait for incoming binding request
   (nio/datagram-receive-rf
    (comp
     receive-stun-rf))
   ;; wait for request
   (drop-while (fn [{:stun/keys [message]}]
                 (prn ::message message)
                 (not= :request message)))
   (rf/one-rf :stun/message (comp
                             (map :stun/message)))
   ;; create success response
   (nio/datagram-send-rf
    (comp
     (map (fn [{:context/keys [buf remote-password]
                :stun/keys [ip]
                :http/keys [host port]
                :as x}]
            (assoc x
                   :stun/buf (-> buf (.clear))
                   :stun/message :success
                   :stun/family :ipv4
                   :stun/port port
                   :stun/ip host
                   :stun/attributes [:xor-mapped-address :message-integrity :fingerprint])))
     (map
      (fn [{:stun/keys [buf] :as x}]
        (assoc x :http/req [(stun/encode x)])))))
   ;; drain buffer
   #_(drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                   (.hasRemaining (block))))
   #_nio/readable-rf))

#_(
   *e
   (in-ns 'jaq.http.xrf.ice)
   )

(def dtls-rf
  "DTLS connection over UDP."
  (comp
   dtls/ssl-rf
   (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                 (nio/read-writable! selection-key)
                 x))
   ;; filter out stun packets
   (fn [rf]
     (let [xf (comp
               (rf/repeatedly-rf
                simple-stun-rf
                #_(nio/datagram-receive-rf
                   (comp
                    receive-stun-rf))))
           xrf (xf (rf/result-fn))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {{:keys [reserve commit block decommit] :as bip} :nio/in
                :as x}]
          (let [bb (block)]
            (cond
              (not (.hasRemaining bb))
              (rf acc x)

              :else
              (let [byte (.get bb)]
                (if (and (> byte 19) (< byte 64))
                  (rf acc x)
                  (do
                    (prn ::filtering ::stun)
                    (xrf acc x)
                    acc)))))))))
   dtls/handshake-rf
   (rf/once-rf (fn [{:nio/keys [selection-key] :as x}]
                 (nio/readable! selection-key)
                 x))
   #_(rf/debug-rf ::handshake)
   (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/in}]
                 (not (.hasRemaining (block)))))
   ;; receive init
   (dtls/receive-ssl-rf
    (comp
     sctp/sctp-rf
     (map (fn [{:sctp/keys [chunks] :as x}]
            (prn ::chunk ::in (count chunks) #_(->> chunks first (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {})))
            x))))


   ;; verification tag of sender
   (rf/one-rf :context/chunk (comp
                              (map (fn [{:sctp/keys [chunks] :as x}]
                                     (prn ::chunks chunks)
                                     (assoc x :sctp/chunk (-> chunks first :sctp/chunk))))
                              (map (fn [{:sctp/keys [chunk] :as x}]
                                     (select-keys chunk [:sctp/init-tag :sctp/src :sctp/dst
                                                         :sctp/window :sctp/initial-tsn
                                                         :sctp/inbound :sctp/outbound])))
                              (map (fn [x]
                                     (prn ::context ::chunk x)
                                     x))))

   ;; our tsn cookie etc.
   (rf/one-rf :context/sctp (comp
                             (map (fn [{:sctp/keys [chunk] :as x}]
                                    {:sctp/cookie (-> (sctp/random-int) (biginteger) (.toByteArray))
                                     :sctp/init-tag (-> (sctp/random-int) (bit-and 0xffffffff))
                                     :sctp/initial-tsn (-> (sctp/random-int) (bit-and 0xffffffff))}))))
   ;; send init-ack
   (dtls/request-ssl-rf
    (comp
     (map (fn [{:context/keys [buf chunk]
                {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                ;;:contex/keys [chunk]
                :as x}]
            (assoc x
                   :sctp/buf (-> buf (.clear))
                   :sctp/chunks [{:chunk :init-ack :chunk-flags 0}]
                   :sctp/cookie cookie
                   :sctp/init-tag init-tag
                   :sctp/initial-tsn initial-tsn
                   :sctp/src (:sctp/src chunk)
                   :sctp/dst (:sctp/dst chunk)
                   :sctp/outbound (:sctp/outbound chunk)
                   :sctp/inbound (:sctp/inbound chunk)
                   :sctp/window (:sctp/window chunk)
                   :sctp/tag (:sctp/init-tag chunk))))
     (map (fn [{:sctp/keys [chunk] :as x}]
            (prn ::chunk ::out (->> x
                                    (filter (fn [[k v]]
                                              (and
                                               (not= k :sctp/chunk)
                                               (= (namespace k) "sctp"))))
                                    (into {})))
            x))
     (map
      (fn [{:stun/keys [buf] :as x}]
        (assoc x :http/req [(sctp/encode x)])))))
   ;; drain out
   (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                 (.hasRemaining (block))))
   (map (fn [x]
          (dissoc x :sctp/chunk :sctp/chunks)))
   ;; should be cookie echo and message open
   (dtls/receive-ssl-rf
    (comp
     sctp/sctp-rf
     (map (fn [{:sctp/keys [chunks] :as x}]
            (prn ::chunk ::in (count chunks) #_(->> chunks first (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {})))
            x))
     #_(map (fn [{:sctp/keys [chunks] :as x}]
              (assoc x :sctp/chunk (-> chunks first :sctp/chunk))))))

   (rf/one-rf :sctp/chunks (map (fn [x] (-> x :sctp/chunks))))
   ;; data channel
   (rf/one-rf :context/datachannel (comp
                                    (map (fn [{:sctp/keys [chunks] :as x}]
                                           (->> chunks
                                                (map :sctp/chunk)
                                                (filter (fn [{:sctp/keys [chunk]}] (= :data chunk)))
                                                (map (fn [x]
                                                       (->> x
                                                            (filter
                                                             (fn [[k v]] (contains? #{"sctp" "datachannel"} (namespace k))))
                                                            (into {}))))
                                                (first))))))

   #_(->> y :sctp/chunks
          (map :sctp/chunk)
          (filter (fn [{:sctp/keys [chunk]}] (= :data chunk)))
          (map (fn [x]
                 (->> x
                      (filter
                       (fn [[k v]] (contains? #{"sctp" "datachannel"} (namespace k))))
                      (into {}))))
          (first))
   #_(
      (into [] (comp
                (map (fn [{:sctp/keys [chunks] :as x}]
                       (->> chunks
                            (map :sctp/chunk)
                            (filter (fn [{:sctp/keys [chunk]}] (= :data chunk)))
                            (map (fn [x]
                                   (->> x
                                        (filter
                                         (fn [[k v]] (contains? #{"sctp" "datachannel"} (namespace k))))
                                        (into {}))))
                            (first))))) [y])

      (->> [y] (map :sctp/chunks) (map :sctp/chunk) (count))
      )

   ;; send cookie ack, sack and message ack
   (dtls/request-ssl-rf
    (comp
     (map (fn [{:context/keys [buf chunk]
                :sctp/keys [chunks]
                {:sctp/keys [window]} :context/chunk
                {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                :as x}]
            (assoc x
                   :sctp/buf (-> buf (.clear))
                   ;; sack
                   :sctp/tsn-ack (->> chunks
                                      (map :sctp/chunk)
                                      (filter (fn [{:datachannel/keys [message]}] (= message :message/open)))
                                      (map :sctp/tsn)
                                      (first))
                   :sctp/window window
                   :sctp/gaps [] :sctp/dups []
                   ;; message ack
                   :sctp/tsn initial-tsn
                   :sctp/stream (->> chunks
                                     (map :sctp/chunk)
                                     (filter (fn [{:datachannel/keys [message]}] (= message :message/open)))
                                     (map :sctp/stream)
                                     (first))
                   :sctp/sequence (->> chunks
                                       (map :sctp/chunk)
                                       (filter (fn [{:datachannel/keys [message]}] (= message :message/open)))
                                       (map :sctp/sequence)
                                       (first))
                   :sctp/protocol (->> chunks
                                       (map :sctp/chunk)
                                       (filter (fn [{:datachannel/keys [message]}] (= message :message/open)))
                                       (map :sctp/protocol)
                                       (first))
                   :datachannel/message :message/ack
                   ;; chunks
                   :sctp/chunks [{:chunk :cookie-ack :chunk-flags 0}{:chunk :sack :chunk-flags 0}{:chunk :data :chunk-flags 3}]
                   ;; packet
                   :sctp/src (:sctp/src chunk)
                   :sctp/dst (:sctp/dst chunk)
                   :sctp/tag (:sctp/init-tag chunk))))
     (map (fn [{:sctp/keys [chunk] :as x}]
            (prn ::chunk ::out (->> x
                                    (filter (fn [[k v]]
                                              (and
                                               (not= k :sctp/chunk)
                                               (= (namespace k) "sctp"))))
                                    (into {})))
            x))
     (map
      (fn [{:stun/keys [buf] :as x}]
        (assoc x :http/req [(sctp/encode x)])))))
   (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                 (.hasRemaining (block))))

   ;; receive sack for message ack
   (dtls/receive-ssl-rf
    (comp
     sctp/sctp-rf
     (map (fn [{:sctp/keys [chunks] :as x}]
            (prn ::chunk ::in (count chunks) #_(->> chunks (map :sctp/chunk) (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {})))
            x))))
   (rf/one-rf :sctp/chunks (map (fn [x] (-> x :sctp/chunks))))
   (rf/one-rf :context/tsn-ack (comp
                                (map (fn [{:sctp/keys [chunks] :as x}]
                                       (->> chunks
                                            (map :sctp/chunk)
                                            (filter (fn [{:sctp/keys [chunk]}] (= chunk :sack)))
                                            (map :sctp/tsn-ack)
                                            (first))))))

   ;; send message open
   ;; TODO: add as a chunk to previous message?
   #_(comp
    (dtls/request-ssl-rf
     (comp
      (map (fn [{:context/keys [buf chunk datachannel]
                 :sctp/keys [chunks]
                 {:sctp/keys [window]} :context/chunk
                 {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                 {:datachannel/keys [label reliability protocol priority]
                  :sctp/keys [sequence stream channel]} :context/datachannel
                 :as x}]
             (assoc x
                    :sctp/buf (-> buf (.clear))
                    :sctp/src (:sctp/src chunk)
                    :sctp/dst (:sctp/dst chunk)
                    :sctp/tag (:sctp/init-tag chunk)
                    :sctp/window window
                    :sctp/gaps [] :sctp/dups []
                    :sctp/chunks [{:chunk :data :chunk-flags 3}]
                    ;; message open on new stream
                    :sctp/tsn (->> chunks
                                   (map :sctp/chunk)
                                   (filter (fn [{:sctp/keys [chunk]}] (= chunk :sack)))
                                   (map :sctp/tsn-ack)
                                   (first)
                                   (inc))
                    :sctp/channel channel
                    :sctp/stream stream #_(inc stream)
                    :sctp/sequence #_sequence (inc sequence)
                    :sctp/protocol :webrtc/dcep
                    :datachannel/message :message/open
                    :datachannel/priority priority
                    :datachannel/reliability reliability
                    :datachannel/label label
                    :datachannel/protocol protocol)))
      (map (fn [{:sctp/keys [chunk] :as x}]
             (prn ::chunk ::out (->> x
                                     (filter (fn [[k v]]
                                               (and
                                                (not= k :sctp/chunk)
                                                (contains? #{"sctp" "datachannel"} (namespace k)))))
                                     (into {})
                                     #_((fn [x] (def y x)))))
             x))
      (map
       (fn [{:stun/keys [buf] :as x}]
         (assoc x :http/req [(sctp/encode x)])))))

    ;; receive sack for message open, message ack
    (dtls/receive-ssl-rf
     (comp
      sctp/sctp-rf
      (map (fn [{:sctp/keys [chunks] :as x}]
             (prn ::chunk ::in (count chunks) (->> chunks (map :sctp/chunk) (map :sctp/chunk)))
             x))))

    (rf/one-rf :context/tsn-ack (comp
                                 (map (fn [{:sctp/keys [chunks] :as x}]
                                        (->> chunks
                                             (map :sctp/chunk)
                                             (filter (fn [{:sctp/keys [chunk]}] (= chunk :sack)))
                                             (map :sctp/tsn-ack)
                                             (first))))))
    ;; send sack for message ack
    (dtls/request-ssl-rf
     (comp
      (map (fn [{:context/keys [buf chunk]
                 :sctp/keys [chunks]
                 {:sctp/keys [window]} :context/chunk
                 {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                 :as x}]
             (assoc x
                    :sctp/buf (-> buf (.clear))
                    ;; sack
                    :sctp/window window
                    :sctp/gaps [] :sctp/dups []
                    :sctp/tsn-ack (->> chunks
                                       (map :sctp/chunk)
                                       (filter (fn [{:datachannel/keys [message]}] (= message :message/ack)))
                                       (map :sctp/tsn)
                                       (first))
                    :sctp/tsn (->> chunks
                                   (map :sctp/chunk)
                                   (filter (fn [{:sctp/keys [chunk]}] (= chunk :sack)))
                                   (map :sctp/tsn-ack)
                                   (first)
                                   (inc))
                    ;; chunks
                    :sctp/chunks [{:chunk :sack :chunk-flags 0}]
                    ;; packet
                    :sctp/src (:sctp/src chunk)
                    :sctp/dst (:sctp/dst chunk)
                    :sctp/tag (:sctp/init-tag chunk))))
      (map (fn [{:sctp/keys [chunk] :as x}]
             (prn ::chunk ::out (->> x
                                     (filter (fn [[k v]]
                                               (and
                                                (not= k :sctp/chunk)
                                                (= (namespace k) "sctp"))))
                                     (into {})))
             x))
      (map
       (fn [{:stun/keys [buf] :as x}]
         (assoc x :http/req [(sctp/encode x)]))))))

   ;; message
   (dtls/receive-ssl-rf
      (comp
       sctp/sctp-rf
       (map (fn [{:sctp/keys [chunks] :as x}]
              (prn ::chunk ::in (count chunks) (->> chunks (map :sctp/chunk) (map :sctp/chunk)))
              x))))
   ;; sack and message echo
   #_(
      (-> y :context/tsn-ack)
      (-> y :sctp/chunks (first) :sctp/chunk :datachannel/payload)
      (-> y :sctp/chunks (first) :sctp/chunk :sctp/sequence)
      (->> y :sctp/chunks (map :sctp/chunk)
           (filter (fn [{:sctp/keys [protocol]}] (= protocol :webrtc/string)))
           (map :sctp/tsn) (first))
      )
   ;; TODO: clean up multiple chunks mess
   (rf/one-rf :sctp/chunk (map (fn [{:sctp/keys [chunks] :as x}]
                                 (->> chunks (first) :sctp/chunk))))
   (dtls/request-ssl-rf
    (comp
     (map (fn [{:context/keys [buf chunk tsn-ack]
                :sctp/keys [chunks]
                {:sctp/keys [sequence stream protocol]
                 :datachannel/keys [payload]} :sctp/chunk
                {:sctp/keys [window]} :context/chunk
                {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                {:sctp/keys [stream]} :context/datachannel
                :as x}]
            (assoc x
                   :sctp/buf (-> buf (.clear))
                   ;; sack
                   :sctp/window window
                   :sctp/gaps [] :sctp/dups []
                   :sctp/tsn-ack (->> chunks
                                      (map :sctp/chunk)
                                      (filter (fn [{:sctp/keys [protocol]}] (= protocol :webrtc/string)))
                                      (map :sctp/tsn)
                                      (first))
                   ;; chunks
                   :sctp/chunks [{:chunk :sack :chunk-flags 0}{:chunk :data :chunk-flags 3}]
                   ;; message echo
                   :sctp/tsn (inc tsn-ack)
                   :sctp/stream stream #_(inc stream)
                   :sctp/sequence sequence
                   :sctp/protocol protocol
                   :datachannel/payload (str "echo: " payload)
                   ;; packet
                   :sctp/src (:sctp/src chunk)
                   :sctp/dst (:sctp/dst chunk)
                   :sctp/tag (:sctp/init-tag chunk))))
     (map (fn [{:sctp/keys [chunk] :as x}]
            (def y x)
            (prn ::chunk ::out (->> x
                                    (filter (fn [[k v]]
                                              (and
                                               (not= k :sctp/chunk)
                                               (contains? #{"sctp" "datachannel"} (namespace k)))))
                                    (into {})))
            x))
     (map
      (fn [{:stun/keys [buf] :as x}]
        (assoc x :http/req [(sctp/encode x)])))))

   ;; sack for message echo
   (dtls/receive-ssl-rf
    (comp
     sctp/sctp-rf
     (map (fn [{:sctp/keys [chunks] :as x}]
            (prn ::chunk ::in (count chunks) (->> chunks (map :sctp/chunk) (map :sctp/chunk)))
            x))))

   ;; heartbeat ack
   #_(dtls/request-ssl-rf
      (comp
       (map (fn [{:context/keys [buf chunk]
                  :sctp/keys [tsn heartbeat]
                  {:sctp/keys [window]} :context/chunk
                  {:sctp/keys [cookie init-tag initial-tsn]} :context/sctp
                  :as x}]
              (assoc x
                     :sctp/buf (-> buf (.clear))
                     :sctp/chunks [{:chunk :heartbeat-ack :chunk-flags 0}]
                     :sctp/src (:sctp/src chunk)
                     :sctp/dst (:sctp/dst chunk)
                     :sctp/tag (:sctp/init-tag chunk))))
       (map (fn [{:sctp/keys [chunk] :as x}]
              (prn ::chunk ::out (->> x
                                      (filter (fn [[k v]]
                                                (and
                                                 (not= k :sctp/chunk)
                                                 (contains? #{"sctp" "datachannel"} (namespace k)))))
                                      (into {})))
              x))
       (map
        (fn [{:stun/keys [buf] :as x}]
          (assoc x :http/req [(sctp/encode x)])))))

   ;; heartbeat again?
   #_(dtls/receive-ssl-rf
      (comp
       sctp/sctp-rf
       (map (fn [{:sctp/keys [chunk] :as x}]
              (def y x)
              (prn ::chunk ::second (->> chunk (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {})))
              x))
       (take 1)))

   #_(rf/repeatedly-rf
      (comp
       (dtls/receive-ssl-rf
        (comp
         sctp/sctp-rf
         (map (fn [{:sctp/keys [chunk] :as x}]
                (def y x)
                (prn ::chunk (->> chunk (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {})))
                x))
         (take 1)))

       ;; drain out
       #_(drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                       (.hasRemaining (block))))))
   nio/close-connection))

#_(
   *e
   *ns*
   (in-ns 'jaq.http.xrf.ice)
   (require 'jaq.http.xrf.ice :reload)
   (->> y :sctp/chunks (map (fn [{:sctp/keys [chunk]}]
                              (->> chunk (filter (fn [[k v]] (= (namespace k) "datachannel"))) (into {}))
                              )))

   (->> y :sctp/chunks (map (fn [{:sctp/keys [chunk]}]
                              (->> chunk :sctp/chunk))))
   (->> y :sctp/chunks (map :sctp/chunk) (map :sctp/sequence))
   (->> y :sctp/chunks (map :sctp/chunk) (map :sctp/chunk-flags))

   (->> y :context/tsn-ack)
   (->> y :sctp/sequence)

   (->> y :context/vacc)
   (->> y :context/packet (map (fn [x] (bit-and x 0xff))))
   (->> y :sctp/buf)
   (->> y :sctp/chunk :sctp/random)
   (->> y :sctp/chunk :sctp/chunk)
   (->> y :sctp/chunk (filter (fn [[k v]] (= (namespace k) "sctp"))) (into {}))

   (->> y :context/sctp)

   ;; INIT
   ;; sctp header
   (let [buf (->> y :context/vacc (byte-array) (ByteBuffer/wrap))
         ;; common header
         src (.getShort buf)
         dst (.getShort buf)
         tag (-> (.getInt buf) (bit-and 0xffffffff))
         checksum (-> (.getInt buf) (bit-and 0xffffffff))
         ;; chunk
         chunk-type (-> buf (.get) (bit-and 0xff))
         chunk-flags (-> buf (.get) (bit-and 0xff))
         chunk-length (-> buf (.getShort) (bit-and 0xffff))
         ;; INIT (1)
         init-tag (-> (.getInt buf) (bit-and 0xffffffff))
         window (-> (.getInt buf) (bit-and 0xffffffff))
         outbound (-> buf (.getShort) (bit-and 0xffff))
         inbound (-> buf (.getShort) (bit-and 0xffff))
         tsn (-> (.getInt buf) (bit-and 0xffffffff))
         ]
     {:sctp/src src :sctp/dst dst :sctp/tag tag :sctp/checksum checksum
      :chunk/type chunk-type :chunk/flags chunk-flags :chunk/length chunk-length
      :init/tag init-tag :init/window window :init/outbound outbound :init/inbound inbound
      :init/tsn tsn}
     )

   (let [{{:keys [reserve commit block decommit] :as bip} :nio/in} y
         buf (-> (block) (.duplicate))
         vacc (loop [acc [] b (.get buf)]
                (if-not (.hasRemaining buf)
                  acc
                  (recur (conj acc (bit-and b 0xff))  (.get buf))))
         xf (comp)]
     vacc
     )

   )

(def stun-rf
  (comp
   (rf/one-rf :context/buf (comp
                            (map (fn [x]
                                   (assoc x :context/buf (ByteBuffer/allocate 150))))
                            (map :context/buf)) )
   (nio/datagram-channel-rf
    (comp
     nio/datagram-read-rf
     (map (fn [{:nio/keys [address] :as x}]
            (if address
              (assoc x
                     :http/host (-> address (.getAddress) (.getHostAddress))
                     :http/port (.getPort address))
              x)))
     nio/datagram-write-rf
     (rf/repeatedly-rf
      (comp
       (nio/datagram-receive-rf
        (comp
         (rf/one-rf
          :udp/protocol
          (comp
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
                                      (stun/decode)
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
                                            (stun/decode-attributes))]
                               (if-not (.hasRemaining buf)
                                 x'
                                 (recur (stun/decode-attributes x'))))
                             x))))
                  (map (fn [{:stun/keys [port ip message length cookie id] :as x}]
                         (prn ::stun message length cookie id)
                         x))
                  (take 1)
                  #_(rf/debug-rf ::request))
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
                     (map (fn [{:context/keys [buf remote-password]
                                :stun/keys [ip]
                                :http/keys [host port]
                                :as x}]
                            (assoc x
                                   :stun/buf (-> buf (.clear))
                                   :stun/message :success
                                   :stun/family :ipv4
                                   :stun/port port
                                   :stun/ip host
                                   :stun/attributes [:xor-mapped-address :message-integrity :fingerprint])))
                     (map
                      (fn [{:stun/keys [buf] :as x}]
                        (assoc x :http/req [(stun/encode x)])))
                     #_(rf/debug-rf ::response)))
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
                                   :stun/id (stun/transaction-id)
                                   :stun/message :request
                                   :stun/password remote-password
                                   :stun/family :ipv4
                                   :stun/port local-port
                                   :stun/ip "192.168.1.140"
                                   :stun/attributes [:username :ice-controlled :use-candidate
                                                     :message-integrity :fingerprint])))
                     (map
                      (fn [{:stun/keys [buf] :as x}]
                        (assoc x :http/req [(stun/encode x)])))
                     (rf/debug-rf ::binding)))
                   (drop-while (fn [{{:keys [reserve commit block decommit] :as bip} :nio/out}]
                                 (.hasRemaining (block))))
                   #_(rf/debug-rf ::sent)
                   nio/readable-rf)
         :success (comp
                   (rf/debug-rf ::success)
                   (map (fn [x]
                          x)))
         :error (comp
                 (rf/debug-rf ::error))})
       #_(rf/debug-rf ::done)))))))

#_(
   (in-ns 'jaq.http.xrf.ice)
   *e
   *ns*
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
                   nio/close-connection))
                 nio/writable-rf))
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
                       (remove (fn [f] (.isLoopbackAddress f)))
                       (map (fn [f] [(.getHostAddress f) (->> (.getAddress f) (map (fn [x] (bit-and 0xff x))))])))))
        (set))

   ;; get all ip addresses
   (let [ip (fn [v]
              (cond
                (= (count v) 4)
                (string/join "."
                             (->> v
                                  (map (fn [e] (bit-and e 0xff)))
                                  (map str)))
                (= (count v) 16)
                (string/join ":"
                             (->> v
                                  (map (fn [e] (bit-and e 0xff)))
                                  (map (fn [x] (Integer/toHexString x)))
                                  (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
                                  (partition 2)
                                  (map (fn [[a b]] (str a b)))))))]
     (->> (NetworkInterface/getNetworkInterfaces)
          (enumeration-seq)
          (mapcat (fn [e]
                    (->> (.getInetAddresses e)
                         (enumeration-seq)
                         (remove (fn [f] (.isLoopbackAddress f)))
                         (map (fn [f] (->> (.getAddress f) (map (fn [x] (bit-and 0xff x))) ip))))))
          (set)))

   )
