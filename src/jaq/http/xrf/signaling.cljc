(ns jaq.http.xrf.signaling
  "Signaling implementaiton.

  Provide a signaling channel to negotiate a WebRTC Data Channel
  between the client and server through ICE.

  This implementation targets the browser as the controlling agent and the
  server as the controlled agent.

  Resources:
  - https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-03
  - https://tools.ietf.org/html/rfc7983
  - https://tools.ietf.org/id/draft-ietf-rtcweb-data-protocol-07.txt"
  #?(:cljs
     (:require [cljs.core]
               [goog.events]
               [clojure.browser.event :refer [IEventType]]
               [clojure.pprint :refer [pprint]]
               [clojure.string :as string]
               [clojure.walk :as walk]
               [goog.dom :as dom]
               #_[garden.core :refer [css]]
               [jaq.http.xrf.html :as html])
     :clj
     (:require [clojure.pprint :refer [pprint]]
               [clojure.data.json :as json]
               [clojure.string :as string]
               [jaq.http.xrf.dtls :as dtls]
               [jaq.http.xrf.http :as http]
               [jaq.http.xrf.ice :as ice]
               [jaq.http.xrf.nio :as nio]
               #_[jaq.http.xrf.repl :refer [send-response-rf]]
               [jaq.http.xrf.rf :as rf]
               [jaq.http.xrf.ssl :as ssl]
               [jaq.http.xrf.stun :as stun]
               [jaq.gcp.appengine :as appengine]
               [jaq.gcp.storage :as storage]))
  #?(:cljs
     (:import [goog.events EventTarget EventType]
              [goog.net XhrIo])
     :clj
     (:import
      [java.net NetworkInterface]
      [java.nio ByteBuffer])))

(defn parse-sdp [s]
  (-> s
      (string/split #"\r\n")
      (->> (mapcat (fn [e] (string/split e #"=")))
           (partition 2)
           (map (fn [[k v]] [(keyword k) v]))
           (group-by (fn [[k v]] k))
           (map (fn [[k v]] [k (->> v (mapcat identity) (remove (fn [e] (= e k))) (vec))]))
           (into {})
           (map (fn [[k v]]
                  (if (= k :a)
                    [k (->> v (map (fn [e] (string/split e #":" 2)))
                            (map (fn [[k v]] [(keyword k) v]))
                            (group-by (fn [[k v]] k))
                            (map (fn [[k v]] [k (->> v (mapcat identity) (remove (fn [e] (= e k))) (vec))]))
                            (into {}))]
                    [k v])))
           (into {}))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.signaling)
   (->> y :http/json :sdp :sdp (parse-sdp))
   )

(defn sdp [{:sdp/keys [port host ip ufrag pwd fingerprint]
            :or {ip "0.0.0.0" ufrag "abcd" pwd "1234567890123456789012"}
            :as x}]
  (->> {:v ["0"] ;; version
        :s ["-"] ;; session name
        :t ["0 0"] ;; start end time
        :c [(str "IN IP4 " ip)] ;; connection data
        :m [(str "application " port " UDP/DTLS/SCTP webrtc-datachannel")] ;; media description
        :o ["- 1234 1 IN IP4 127.0.0.1"] ;; origin
        :a {:ice-ufrag [ufrag] ;; attributes
            :ice-pwd [pwd]
            :setup ["passive"]
            :mid ["0"]
            :sctp-port ["5000"]
            ;; foundation component transport priority address port type
            ;;:candidate [(str "foundation 1 udp 2130706431 " host " " port " typ host")]
            :candidate [(str "foundation 1 udp 2130706431 " host " " port " typ host ")
                        #_(str "foundation 1 udp 2130706431 " host " " port " typ srflx raddr 192.168.1.140 rport " port)
                        (str "foundation 1 udp 2130706431 192.168.1.140" " " port " typ host")]
            :fingerprint [(str "sha-256 " (string/join ":" fingerprint))]}}
       ;; need to order the keys unfortunately
       ((fn [{:keys [v o s t m c a] :as sdp}]
          [[:v v] [:o o] [:s s] [:t t] [:m m] [:c c] [:a a]]))
       (map (fn [[k v]]
              (if (= k :a)
                (->> v (mapcat (fn [[e f]] (->> f (map (fn [g] (str (name k) "=" (name e) ":" g)))))))
                (->> v (map (fn [e] (str (name k) "=" e)))))))
       (mapcat identity)
       (reverse)
       (into [""])
       (reverse)
       (string/join "\r\n")))

#_(
   (->> {:sdp/fingerprint ["12" "13"]
         :sdp/port 2230}
        (sdp)
        (parse-sdp))
   )

#?(:cljs
   (def peer-rf
     (fn [rf]
       (let [peer (volatile! nil)]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:rtc/keys [conf]
                  :or {conf {}}
                  :as x}]
            (when-not @peer
              (vreset! peer (js/RTCPeerConnection. (clj->js conf))))
            (->> (assoc x :rtc/peer @peer)
                 (rf acc)))))))

   :clj :noop)

#?(:cljs
   (def channel-rf
     (fn [rf]
       (let [channel (volatile! nil)]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:rtc/keys [peer channel-name channel-conf]
                  :or {channel-conf {}}
                  :as x}]
            (when-not @channel
              (vreset! channel (.createDataChannel peer channel-name (clj->js channel-conf))))
            (->> (assoc x :rtc/channel @channel)
                 (rf acc)))))))
   :clj :noop)

#?(:cljs
   (extend-protocol IEventType

     js/RTCPeerConnection
     (event-types
       [this]
       (into {}
             (map
              (fn [[k v]]
                [(keyword (.toLowerCase k))
                 v])
              (merge
               #_{:icegatheringstatechange "icegatheringstatechange"}
               (js->clj EventType)))))

     js/RTCDataChannel
     (event-types
       [this]
       (into {}
             (map
              (fn [[k v]]
                [(keyword (.toLowerCase k))
                 v])
              (merge
               #_{:icegatheringstatechange "icegatheringstatechange"}
               (js->clj EventType))))))

   :clj :noop)

(defn await-rf [k f]
  (fn [rf]
    (let [once (volatile! nil)
          result (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:event/keys [src type]
               :as x}]
         (if-not @once
           (do
             (vreset! once true)
             (-> (f x)
                 (.then (fn [y]
                          (rf acc (assoc x k y)))))))
         acc)))))

(defn result-fn []
  (let [result (volatile! nil)]
    (fn
      ([] @result)
      ([acc] acc)
      ([acc x] (vreset! result x) acc))))

(defn async-rf [xf]
  (fn [rf]
    (let [promise (volatile! nil)
          xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:event/keys [src type]
               :as x}]
         (when-not @promise
           (->> (xrf acc (assoc x
                                :context/rf xrf
                                :context/x x))
                (vreset! promise)))
         (->> (assoc x :async/promise xrf)
              (rf acc)))))))

#_(

   (into []
         (comp
          peer-rf
          (async-rf (comp
                     (await-rf :rtc/offer (fn [{:rtc/keys [peer]}] (.createOffer peer)))
                     (map (fn [{:rtc/keys [offer] :as x}]
                            (.info js/console offer)
                            x)))))
         [{}])

   (-> (.createOffer peer)
       (.then (fn [offer]
                (vreset! voffer offer)
                (.info js/console (.-sdp offer))
                (.setLocalDescription peer offer)))
       (.then (fn []
                (-> peer (.-localDescription) (info)))))

   (-> (js/RTCPeerConnection. (clj->js {}))
       (event-types))

   (goog/inherits js/RTCPeerConnection EventTarget)

   (def x
     (->> [{}]
          (into [] (comp
                    peer-rf
                    channel-rf

                    ;; ice state
                    (map (fn [{:rtc/keys [peer] :as x}]
                           (assoc x
                                  :event/src peer
                                  :event/type "icegatheringstatechange")))
                    (html/register-rf
                     (comp
                      (map (fn [{:event/keys [target] :as x}]
                             (assoc x
                                    :rtc/state (some-> target (.-iceGatheringState)))))
                      (drop-while (fn [{:rtc/keys [state]}] (not= state "complete")))
                      (map (fn [{:rtc/keys [peer state]
                                 :as x}]
                             (.info js/console "state" state)
                             (.info js/console (-> peer (.-localDescription) (.-sdp)))
                             x))))

                    ;; ice candidates
                    (map (fn [{:rtc/keys [peer] :as x}]
                           (assoc x
                                  :event/src peer
                                  :event/type "icecandidate")))
                    (html/register-rf
                     (comp
                      (map (fn [{:event/keys [event] :as x}]
                             #_(.info js/console "candidate" event)
                             (assoc x
                                    :rtc/candidate (some-> event (.-event_) (.-candidate)))))
                      (remove (fn [{:rtc/keys [candidate]}] (nil? candidate)))
                      (map (fn [{:rtc/keys [candidate]
                                 :as x}]
                             (.info js/console "candidate" candidate)
                             x))))

                    ;; create offer
                    (async-rf (comp
                               (await-rf :rtc/offer (fn [{:rtc/keys [peer]}] (.createOffer peer)))
                               (await-rf :rtc/descriptor (fn [{:rtc/keys [peer offer]}]
                                                           (.setLocalDescription peer offer)))
                               (map (fn [{:rtc/keys [peer offer] :as x}]
                                      (.info js/console "offer" (-> offer (.-sdp)))
                                      x))))))))

   (defn offer []
     (let [channel-name "foobar"
           conf {} #_{:iceServers [{:urls "stun:stun.l.google.com:19302"}]
                      :iceCandidatePoolSize 1}
           constraints {:video false :audio true}
           peer (js/RTCPeerConnection. (clj->js conf))
           channel (.createDataChannel peer channel-name)
           info (fn [e] (.info js/console e))]
       (vreset! vpeer peer)
       (vreset! vchannel channel)
       ;; connection
       (set! (.-onicecandidate peer) info)
       (set! (.-onnegotiationneeded peer) info)
       (set! (.-oniceconnectionstatechange peer) info)
       (set! (.-onicegatheringstatechange peer) (fn [e]
                                                  (let [pc (-> e (.-target))
                                                        state (-> pc (.-iceGatheringState))
                                                        desc (js/RTCSessionDescription. (clj->js {:sdp @vanswer :type "answer"}))]
                                                    (when (= state "complete")
                                                      (info pc)
                                                      ;; set remote descriptor
                                                      (-> pc (.setRemoteDescription desc)
                                                          (.then (fn [] (info desc))))))))
       ;; channel
       (set! (.-onopen channel) info)
       (set! (.-onclose channel) info)
       (-> peer (.getConfiguration) (info))
       (vreset! voffer nil)
       (-> (.createOffer peer)
           (.then (fn [offer]
                    (vreset! voffer offer)
                    (.info js/console (.-sdp offer))
                    (.setLocalDescription peer offer)))
           (.then (fn []
                    (-> peer (.-localDescription) (info)))))
       @voffer)))


(def connect-rf
  (comp
   (comp
    #?(:cljs
       (comp
        html/render-rf
        (map (fn [x]
               ;; clean up event handler
               (some-> (dom/getDocument)
                       (.querySelector "button")
                       (goog.events/removeAll))
               x))
        (fn [rf] ;; TODO: should come from NetManager pool
          (let [xhr (volatile! nil)]
            (fn
              ([] (rf))
              ([acc] (rf acc))
              ([acc {:event/keys [src target type event]
                     :as x}]
               (when-not @xhr
                 (vreset! xhr (XhrIo.)))
               (->> (assoc x :net/xhr @xhr)
                    (rf acc))))))
        ;; data channel
        peer-rf
        channel-rf
        ;; ice state
        (map (fn [{:rtc/keys [peer] :as x}]
               (assoc x
                      :event/src peer
                      :event/type "icegatheringstatechange")))
        (html/register-rf
         (comp
          (map (fn [{:event/keys [target] :as x}]
                 (assoc x
                        :rtc/state (some-> target (.-iceGatheringState)))))
          (drop-while (fn [{:rtc/keys [state]}] (not= state "complete")))
          (map (fn [{:rtc/keys [peer]
                     :component/keys [state]
                     :as x}]
                 (.info js/console (-> peer (.-localDescription) (.-sdp)))
                 (vswap! state assoc :sdp (-> peer (.-localDescription)))
                 x))
          ;; activate connect button
          ;; TODO: this wipes the click handler
          #_(map (fn [x]
                   (assoc x
                          :event/src (dom/getElement "form")
                          :dom/hiccup [:form#form
                                       [:label "Peer Connection"]
                                       [:button#submit {:type "button"} "Connect"]])))
          #_html/render-rf))
        ;; data channel
        (map (fn [{:rtc/keys [channel] :as x}]
               (assoc x
                      :event/src channel
                      :event/type "open")))
        (html/register-rf
         (comp
          (map (fn [{:event/keys [target event]
                     :rtc/keys [channel peer]
                     :as x}]
                 (.info js/console "open" target)
                 #_(-> channel (.send (.now js/performance)))
                 (-> peer (.getStats) (.then
                                       (fn [e]
                                         (->> e (.values)
                                              (.from js/Array)
                                              (.stringify js/JSON)
                                              (.info js/console)
                                              #_(.send channel))
                                         (.send channel (.repeat "foobar" 20)))))
                 #_(-> channel (.send (.now js/performance)))
                 x))))
        (map (fn [{:rtc/keys [channel] :as x}]
               (assoc x
                      :event/src channel
                      :event/type "message")))
        (html/register-rf
         (comp
          (map (fn [{:event/keys [target event]
                     :rtc/keys [channel]
                     :as x}]
                 (let [end (.now js/performance)
                       ;;start (-> event (.-event_) (.-data) (js/parseFloat))
                       ms 0 #_(- end start)]
                   (.info js/console "message " (-> event (.-event_) (.-data)))
                   (.info js/console "roundtrip " ms "ms")
                   (assoc x
                          ;;:context/start start
                          :context/end end
                          :context/roundtrip ms))))
          (map (fn [{:component/keys [state]
                     :context/keys [roundtrip]
                     :event/keys [src target type event]
                     :as x}]
                 (assoc x
                        :event/src (dom/getElement "info")
                        :dom/hiccup [:div
                                     [:label (str "Roundtrip: " roundtrip " ms ")]])))
          html/render-rf))
        ;; create offer
        (async-rf (comp
                   (await-rf :rtc/offer (fn [{:rtc/keys [peer]}] (.createOffer peer)))
                   (await-rf :rtc/descriptor (fn [{:rtc/keys [peer offer]}]
                                               (.setLocalDescription peer offer)))
                   (map (fn [{:rtc/keys [peer offer]
                              :component/keys [state]
                              :as x}]
                          (.info js/console "offer" (-> offer (.-sdp)))
                          x))))
        (map (fn [{:rtc/keys [] :as x}]
               (assoc x
                      :event/src (dom/getElement "submit")
                      :event/type "click")))
        ;; form handler
        (html/register-rf
         (comp
          (comp
           (fn [rf]
             (let [vstate (volatile! nil)]
               (fn
                 ([] (rf))
                 ([acc] (rf acc))
                 ([acc {:event/keys [src target type event]
                        :component/keys [state]
                        :as x}]
                  (.preventDefault event)
                  (rf acc x)))))
           (map (fn [{:component/keys [state]
                      :event/keys [src target type event]
                      :as x}]
                  (assoc x
                         :event/src (dom/getElement "info")
                         :dom/hiccup [:div
                                      [:label "SDP: " (:sdp @state)]])))
           html/render-rf)
          ;; trigger server request
          (comp
           (map (fn [{:net/keys [xhr]
                      :component/keys [state]
                      :as x}]
                  (assoc x
                         :net/uri (str "/remote?ns=jaq.http.xrf.signaling&var=connect-rf")
                         :net/method :POST
                         :net/headers {:content-type "application/json"}
                         :net/content @state
                         :event/src xhr
                         :event/type "complete" #_(get html/net-events :complete))))
           (map (fn [{:net/keys [xhr uri method content headers]
                      :event/keys [type]
                      :as x}]
                  (.info js/console "requesting " uri " " type)
                  (.send xhr uri (name method)
                         (->> content (clj->js) (.stringify js/JSON))
                         (-> headers (clj->js)))
                  x))))))
       :clj
       ;; fallthrough
       (comp rf/identity-rf)))

   ;; this should be on the server
   (comp
    #?(:cljs
       (comp
        (map (fn [x]
               (.info js/console x)
               x))
        html/identity-rf)

       ;; server handler
       ;; coordinate exchanging of ICE candidate
       :clj
       (comp
        (rf/one-rf :context/client (comp
                                    (map :nio/selection-key)))
        ;; parse post body
        (nio/receive-rf
         (comp
          http/chunked-rf
          http/text-rf
          nio/body-rf))
        #_(rf/debug-rf ::json)
        (rf/one-rf :ssl/cert (comp
                              (map (fn [x] (assoc x :ssl/cert (dtls/self-cert :cert/alias "server"))))
                              (map :ssl/cert)))
        (rf/one-rf :context/offer (comp
                                   (map (fn [{:http/keys [json] :as x}]
                                          (->> json :sdp :sdp (parse-sdp))))))
        (rf/one-rf :context/remote-password (comp
                                             (map (fn [{:context/keys [offer]}]
                                                    (->> offer :a :ice-pwd (first))))))
        (rf/one-rf :context/remote-ufrag (comp
                                          (map (fn [{:context/keys [offer]}]
                                                 (->> offer :a :ice-ufrag (first))))))
        (rf/one-rf :context/remote-host (comp
                                         (map (fn [{:context/keys [offer]}]
                                                (->> offer
                                                     :a
                                                     :candidate
                                                     (sort-by (fn [e] (->> (string/split e #"\s") (drop 3) (first))))
                                                     (first)
                                                     ((fn [e]
                                                        (prn ::candidate e)
                                                        (->> (string/split e #"\s") (drop 4) (take 2)
                                                             (partition 2) (map (fn [[e f]] {:host e :port (Integer/parseInt f)})) (first))))
                                                     )))))
        (map (fn [{:http/keys [json]
                   :context/keys [offer]
                   :ssl/keys [cert]
                   {:cert/keys [fingerprint]} :ssl/cert
                   :as x}]
               (assoc x
                      :context/bip-size (* 20 4096)
                      :ssl/packet-size (* 2 1024)
                      :ssl/mode :server
                      :ssl/certs [cert]
                      :sdp/fingerprint fingerprint
                      :stun/password "1234567890123456789012"
                      :stun/ufrag "abcd")))
        ;; create UDP channel and wait for STUN results
        (fn [rf]
          (let [once (volatile! false)
                buf (ByteBuffer/allocate 150)
                client (volatile! nil)
                yf (comp
                    #_(map (fn [x]
                             (assoc x :context/buf buf)))
                    nio/datagram-read-rf
                    (map (fn [{:nio/keys [address] :as x}]
                           (if address
                             (assoc x
                                    :http/host (-> address (.getAddress) (.getHostAddress))
                                    :http/port (.getPort address))
                             x)))
                    nio/datagram-write-rf
                    (rf/one-rf :context/sent
                               (rf/repeat-rf
                                5
                                (comp
                                 (map (fn [{:context/keys [remote-host] :as x}]
                                        (assoc x
                                               :http/host (:host remote-host)
                                               :http/port (:port remote-host))))
                                 (nio/datagram-send-rf
                                  (comp
                                   (map (fn [{:http/keys [host port]
                                          :context/keys [remote-password remote-ufrag]
                                          :stun/keys [ip port ufrag password]
                                          :as x}]
                                          (assoc x
                                                 :stun/buf (ByteBuffer/allocate 100)
                                                 :stun/id (stun/transaction-id)
                                                 :stun/message :request
                                                 :stun/password remote-password
                                                 :stun/username (str remote-ufrag ":" ufrag)
                                                 :stun/family :ipv4
                                                 :stun/port port
                                                 :stun/ip ip
                                                 :stun/attributes [:username :ice-controlled #_:use-candidate
                                                                   :message-integrity :fingerprint])))
                                   (map (fn [x]
                                          (assoc x :http/req [(stun/encode x)]))))))))
                    #_(rf/repeat-rf 5 ice/simple-stun-rf)
                    #_ice/simple-stun-rf
                    ice/dtls-rf)
                yrf (yf (rf/result-fn))
                xf (comp
                    (ice/data-channel-rf
                     (comp
                      #_(map (fn [x]
                               (assoc x :context/buf buf)))
                      stun/stun-host-rf
                      stun/discover-rf
                      (fn [rf]
                        (let [once (volatile! nil)]
                          (fn
                            ([] (rf))
                            ([acc] (rf acc))
                            ([acc {:context/keys [callback-rf callback-x remote-host]
                                   :nio/keys [selection-key]
                                   :stun/keys [ip port]
                                   :as x}]
                             (when-not @once
                               (do
                                 (def y x)
                                 (prn ::remote-host remote-host)
                                 (prn ::stun ip port)
                                 (prn ::sk (-> selection-key (.channel) (.socket) (.getLocalPort)) selection-key)
                                 ;; park datagram channel
                                 #_(.interestOps selection-key nio/read-op)
                                 (.interestOps selection-key nio/write-op)
                                 (let [{client-x :context/x
                                        :as client-attachment} (.attachment selection-key)]
                                   (->> (assoc client-attachment
                                               :context/rf yrf
                                               :context/x x)
                                        (.attach selection-key)))
                                 ;; activate original request channel
                                 (-> callback-x :nio/selection-key (nio/writable!))
                                 (vreset! once true)))
                             (->> #_x (assoc x
                                             :stun/ip #_"35.206.112.7" "192.168.1.140"
                                             :stun/port #_10001 (-> selection-key (.channel) (.socket) (.getLocalPort)))
                                  (rf acc))))))))
                    nio/writable-rf
                    (drop-while (fn [{:stun/keys [ip port]}]
                                  (prn ::stun ip port)
                                  (and (not ip) (not port)))))
                xrf (xf (rf/result-fn))]
            (fn
              ([] (rf))
              ([acc] (rf acc))
              ([acc {:nio/keys [selection-key in out selector]
                     :context/keys [remote-host]
                     original-rf :context/rf
                     original-x :context/x
                     :as x}]
               (when-not @once
                 (prn ::remote-host ::once remote-host)
                 (->> (assoc x
                             :context/buf buf
                             :context/callback-rf rf
                             :context/callback-x x)
                      (xrf acc))
                 #_(->> (xrf) (vreset! client))
                 #_(let [{client-x :context/x
                          :as client-attachment} (.attachment client)
                         client-x (assoc client-x
                                         :context/callback-rf rf
                                         :context/callback-x x)]
                     (->> (assoc client-attachment
                                 :context/rf xrf
                                 :context/x client-x)
                          (.attach client)))
                 ;; park request channel
                 (.interestOps selection-key 0)
                 (prn ::stun ::started @client)
                 (vreset! once true))
               (cond
                 ;; waiting to send response
                 (xrf)
                 (let [{:stun/keys [ip port] :as y} (xrf)]
                   ;; TODO: switch datagram channel rf to ice/dtls-rf
                   (prn ::stun ip port)
                   (if-not (and ip port)
                     acc
                     (rf acc (assoc x
                                    :context/client @client
                                    :context/ip ip
                                    :context/port port))))
                 :else
                 (do
                   (prn ::waiting)
                   acc))))))
        ;; UDP port
        #_(rf/one-rf :http/local-port
                     (comp
                      (ice/data-channel-rf (comp
                                            (rf/one-rf :context/buf (comp
                                                                     (map (fn [x]
                                                                            (assoc x :context/buf (ByteBuffer/allocate 150))))
                                                                     (map :context/buf)))
                                            stun/stun-host-rf
                                            stun/discover-rf
                                            ice/simple-stun-rf
                                            ice/dtls-rf))
                      (map (fn [{:nio/keys [selection-key]
                                 :as x}]
                             (assoc x :http/local-port (-> selection-key (.channel) (.socket) (.getLocalPort)))))
                      (map :http/local-port)))
        ;; restore selection key
        #_(map (fn [{:context/keys [client]
                     :as x}]
                 (assoc x :nio/selection-key client)))
        (map (fn [{:context/keys [client ip port]
                   ;;:stun/keys [fingerprint]
                   :http/keys [local-port]
                   :as x}]
               (assoc x
                      ;;:sdp/fingerprint fingerprint
                      :sdp/host ip ;;"192.168.1.140"
                      :sdp/port port ;;local-port
                      )))
        ;; create SDP answer
        (comp
         nio/writable-rf
         (nio/send-rf (comp
                       (map (fn [x]
                              (assoc x :http/json {:type "answer" :sdp (sdp x)})))
                       #_(rf/debug-rf ::json)
                       (map (fn [{:http/keys [json]
                                  :as x}]
                              (prn ::json json)
                              (assoc x
                                     :http/status 200
                                     :http/reason "OK"
                                     :http/headers {:content-type "application/json"
                                                    :connection "close"}
                                     :http/body (json/write-str json))))
                       nio/response-rf))
         nio/readable-rf)
        #_nio/close-connection
        #_(map (fn [x]
                 (prn ::sent)
                 x)))))

   ;; back on the client
   (comp
    #?(:cljs
       (comp
        ;; register xhr response
        (map (fn [{:net/keys [xhr]
                   :as x}]
               (.info js/console xhr)
               (assoc x
                      :event/src xhr
                      :event/type "complete" #_(get html/net-events :complete))))
        (html/register-rf (comp
                           (map (fn [{:event/keys [target] :as x}]
                                  (assoc x
                                         :net/json (some-> target (.getResponseJson)))))
                           ;; TODO: set remote descriptor
                           (async-rf (comp
                                      (map (fn [{:net/keys [json] :as x}]
                                             (assoc x
                                                    :rtc/remote-description (js/RTCSessionDescription. json))))
                                      (map (fn [{:rtc/keys [peer remote-description] :as x}]
                                             (-> peer (.setRemoteDescription remote-description))
                                             x))))
                           ;; feedback
                           (map (fn [{:component/keys [state]
                                      :net/keys [json]
                                      :as x}]
                                  (.info js/console "json" json)
                                  (assoc x
                                         :event/src (dom/getElement "response")
                                         :dom/hiccup [:div
                                                      [:label "Server response: "]
                                                      [:pre (.stringify js/JSON json)]])))
                           html/render-rf)))
       :clj
       (comp rf/identity-rf)))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.signaling)
   )

#_(
   #?(:cljs
      (defonce init
        (into []
              (comp
               html/render-rf)
              [{:event/src (dom/getElement "app")
                :dom/hiccup [:div
                             [:style {:type "text/css"}
                              (css [:div#main {:font-size "16px"}] [:div#response {:background-color "blue"}])]
                             [:div#main
                              [:form#form
                               [:label "Peer Connection"]
                               [:button#submit {:type "button"} "Connect"]]
                              [:div#info]
                              [:div#response]]]}]))

      :clj :noop))

#?(:cljs
   (defn ^:export x []
     (let [state (volatile! {})
           on-change (fn [k e] (vswap! state assoc k (-> e .-target .-value)))
           on-focus (fn [k e] (-> e .-target .-value (set! (get @state k))))
           x {:component/state state
              :component/css [:div#main {:font-size 16}]
              :event/src (dom/getElement "app")
              :rtc/channel-name "alpeware"
              :rtc/conf {:iceServers [{:urls "stun:stun.l.google.com:19302"}]}
              :dom/hiccup [:div
                           [:style {:type "text/css"}
                            #_(css [:div#main {:font-size "16px"}] [:div#response {:background-color "grey"}])]
                           [:div#main
                            [:form#form
                             [:label "Peer Connection"]
                             [:button#submit {:type "button"} "Connect"]]
                            [:div#info]
                            [:div#response]]]}]
       (first
        (into [] connect-rf [x]))))

   :clj :noop)

#_(
   (x)
   )
#_(
   *e
   *ns*
   (require 'jaq.http.xrf.signaling :reload)
   (in-ns 'jaq.http.xrf.signaling)

   (+ 1 1)
   (-> y :stun/password)
   (-> y :nio/selection-key)
   (-> y :nio/selection-key (.channel) (.socket) (.getLocalSocketAddress))

   (with-out-str (pprint {:foo :bar}))
   ;; init
   (into []
         (comp
          html/render-rf)
         [{:event/src (dom/getElement "app")
           :dom/hiccup [:div
                        [:style {:type "text/css"}
                         (css [:div#main {:font-size "16px"}] [:div#response {:background-color "blue"}])]
                        [:div#main
                         [:form#form
                          [:label "Peer Connection"]
                          [:button#submit {:type "button"} "Connect"]]
                         [:div#info]
                         [:div#response]]]}])

   (def x
     (let [state (volatile! {})
           on-change (fn [k e] (vswap! state assoc k (-> e .-target .-value)))
           on-focus (fn [k e] (-> e .-target .-value (set! (get @state k))))
           x {:component/state state
              :component/css [:div#main {:font-size 16}]
              :event/src (dom/getElement "app")
              :rtc/channel-name "alpeware"
              ;;:rtc/channel-conf {:ordered false}
              :rtc/conf {:iceServers [{:urls "stun:stun.l.google.com:19302"}]}
              :dom/hiccup [:div
                           [:style {:type "text/css"}
                            (css [:div#main {:font-size "16px"}] [:div#response {:background-color "grey"}])]
                           [:div#main
                            [:form#form
                             [:label "Peer Connection"]
                             [:button#submit {:type "button"} "Connect"]]
                            [:div#info]
                            [:div#response]]]}]
       (first
        (into [] connect-rf [x]))))
   (-> x :rtc/peer (.close))
   (-> x :rtc/peer #_(.-readystate))

   (-> x :rtc/peer (.getStats) (.then (fn [e] (->> e (.values) (.from js/Array) (.stringify js/JSON) (.log js/console)))))

   (->> x :rtc/peer (.info js/console))
   (->> x :rtc/channel (.info js/console))

   (-> x :net/xhr (.abort))
   (-> x :rtc/channel (.-id))
   (-> x :rtc/channel (.-label))
   (-> x :rtc/channel (.send "alpeware"))

   (-> x :component/state (deref) (clj->js) (JSON/stringify))
   (->> x :component/state (deref)
        :sdp (JSON/stringify) (JSON/parse) (js->clj) (walk/keywordize-keys)
        :sdp (parse-sdp)
        ((fn [x] (select-keys x [:c :m :a])))
        )
   ;; password
   (->> x :component/state (deref)
        :sdp (JSON/stringify) (JSON/parse) (js->clj) (walk/keywordize-keys)
        :sdp (parse-sdp)
        :a :ice-pwd (first)
        )

   (goog/getCssName "foo")
   (-> (dom/getDocument) (.querySelector "button") (goog.events/removeAll)))

#_(

   ;; navigator.mediaDevices.enumerateDevices

   (-> (.enumerateDevices js/navigator.mediaDevices)
       (.then (fn [devices]
                (->> devices
                     (map (fn [e]
                            (.info js/console e)))
                     (doall)))))

   (->
    (.getDisplayMedia js/navigator.mediaDevices (clj->js {:video true :audo false}))
    (.then (fn [stream]
             (set! (.-srcObject (dom/getElement "video")) stream)
             (.play (dom/getElement "video"))
             (.setAttribute (dom/getElement "video") "width" 640)
             (.setAttribute (dom/getElement "video") "height" 320))))

   (.setAttribute (dom/getElement "video") "width" 1280)
   (.setAttribute (dom/getElement "video") "height" 640)

   (.setAttribute (dom/getElement "video") "width" 640)

   (def vpeer (volatile! nil))
   (def vchannel (volatile! nil))
   (def voffer (volatile! nil))
   (def vanswer (volatile! nil))
   (defn offer []
     (let [channel-name "foobar"
           conf {} #_{:iceServers [{:urls "stun:stun.l.google.com:19302"}]
                      :iceCandidatePoolSize 1}
           constraints {:video false :audio true}
           peer (js/RTCPeerConnection. (clj->js conf))
           channel (.createDataChannel peer channel-name)
           info (fn [e] (.info js/console e))]
       (vreset! vpeer peer)
       (vreset! vchannel channel)
       ;; connection
       (set! (.-onicecandidate peer) info)
       (set! (.-onnegotiationneeded peer) info)
       (set! (.-oniceconnectionstatechange peer) info)
       (set! (.-onicegatheringstatechange peer) (fn [e]
                                                  (let [pc (-> e (.-target))
                                                        state (-> pc (.-iceGatheringState))
                                                        desc (js/RTCSessionDescription. (clj->js {:sdp @vanswer :type "answer"}))]
                                                    (when (= state "complete")
                                                      (info pc)
                                                      ;; set remote descriptor
                                                      (-> pc (.setRemoteDescription desc)
                                                          (.then (fn [] (info desc))))))))
       ;; channel
       (set! (.-onopen channel) info)
       (set! (.-onclose channel) info)
       (-> peer (.getConfiguration) (info))
       (vreset! voffer nil)
       (-> (.createOffer peer)
           (.then (fn [offer]
                    (vreset! voffer offer)
                    (.info js/console (.-sdp offer))
                    (.setLocalDescription peer offer)))
           (.then (fn []
                    (-> peer (.-localDescription) (info)))))
       @voffer))

   (offer)
   @voffer

   ;; btoa(JSON.stringify(pc.localDescription))
   (answer 2231)
   (->> (js/RTCSessionDescription. (clj->js {:sdp @vanswer :type "offer"}))
        (.stringify js/JSON)
        (js/btoa))

   (->> @voffer (.stringify js/JSON) (js/btoa))
   (defn connect [port]
     (answer port)
     (offer))

   (-> @vpeer (.setRemoteDescription (js/RTCSessionDescription. (clj->js {:sdp @vanswer :type "answer"}))))
   (.info js/console (js/RTCSessionDescription. (clj->js {:sdp "sdp" :type "answer"})))
   (->> @voffer (.-type))
   (->> @voffer (.-sdp))
   (->> @vpeer (.-localDescription) (.info js/console))
   (->> @vpeer (.-localDescription) (.toJSON))
   (-> @vpeer (.-localDescription)
       (.-sdp)
       (string/split #"\r\n")
       (->> (mapcat (fn [e] (string/split e #"=")))
            (partition 2)
            (map (fn [[k v]] [(keyword k) v]))
            (group-by (fn [[k v]] k))
            (map (fn [[k v]] [k (->> v (mapcat identity) (remove (fn [e] (= e k))) (vec))]))
            (into {})
            (map (fn [[k v]]
                   (if (= k :a)
                     [k (->> v (map (fn [e] (string/split e #":" 2)))
                             (map (fn [[k v]] [(keyword k) v]))
                             (group-by (fn [[k v]] k))
                             (map (fn [[k v]] [k (->> v (mapcat identity) (remove (fn [e] (= e k))) (vec))]))
                             (into {}))]
                     [k v])))
            (into {})
            :a
            :candidate
            (sort-by (fn [e] (->> (string/split e #"\s") (drop 3) (first))))))

   (defn answer [port]
     (->> {:v ["0"] ;; version
           :s ["-"] ;; session name
           :t ["0 0"] ;; start end time
           :c ["IN IP4 192.168.1.140"] ;; connection data
           :m [(str "application " port " UDP/DTLS/SCTP webrtc-datachannel")] ;; media description
           :o ["- 1234 1 IN IP4 127.0.0.1"] ;; origin
           :a {:ice-ufrag ["abcd"] ;; attributes
               :ice-pwd ["1234567890123456789012"]
               :setup ["passive"]
               :mid ["0"]
               :sctp-port ["5000"]
               :candidate [(str "foundation 1 udp 2130706431 192.168.1.140 " port " typ host")] ;; foundation component transport priority address port type
               :fingerprint [(str "sha-256 " (string/join ":" fingerprint))]}}
          ;; need to order the keys unfortunately
          ((fn [{:keys [v o s t m c a] :as sdp}]
             [[:v v] [:o o] [:s s] [:t t] [:m m] [:c c] [:a a]]))
          (map (fn [[k v]]
                 (if (= k :a)
                   (->> v (mapcat (fn [[e f]] (->> f (map (fn [g] (str (name k) "=" (name e) ":" g)))))))
                   (->> v (map (fn [e] (str (name k) "=" e)))))))
          (mapcat identity)
          (reverse)
          (into [""])
          (reverse)
          (string/join "\r\n")
          (vreset! vanswer)))

   (connect 20)

   @vanswer

   (def fingerprint ["BA" "84" "D0" "2E" "11" "31" "EE" "25" "47" "41" "6D" "F8" "E7" "F6" "A3" "AD" "C9" "39" "25" "49" "E1" "40" "E3" "BB" "F2" "E8" "25" "A8" "5F" "EE" "C1" "C7"])
   (string/join ":" fingerprint)
   (->> (repeatedly
         (fn []
           (->> (.charCodeAt \a) (+ (rand-int 26)) (char))))
        (take 10)
        (apply str))

   (->> sdp :a)

   ;; https://hpbn.co/webrtc/

   (->> [[:foo :bar] [:bar :baz]] (into {}))

   (into []
         (comp
          html/render-rf)
         [{:event/src (dom/getElement "app")
           :dom/hiccup [:div
                        [:div.camera
                         [:video#video]
                         [:button#start "Take Photo"]]
                        [:div#canvas]
                        [:div.output
                         [:img#photo]]]}])

   )
