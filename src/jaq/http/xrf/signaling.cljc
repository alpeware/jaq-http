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
               [clojure.browser.event :refer [IEventType]]
               [clojure.pprint :refer [pprint]]
               [clojure.string :as string]
               [clojure.walk :as walk]
               [goog.dom :as dom]
               [garden.core :refer [css]]
               [jaq.http.xrf.html :as html])
     :clj
     (:require [clojure.pprint :refer [pprint]]
               [clojure.data.json :as json]
               [clojure.string :as string]
               [jaq.http.xrf.dtls :as dtls]
               [jaq.http.xrf.http :as http]
               [jaq.http.xrf.ice :as ice]
               [jaq.http.xrf.nio :as nio]
               [jaq.http.xrf.repl :refer [send-response-rf]]
               [jaq.http.xrf.rf :as rf]
               [jaq.http.xrf.ssl :as ssl]
               [jaq.http.xrf.stun :as stun]
               [jaq.gcp.appengine :as appengine]
               [jaq.gcp.storage :as storage]))
  #?(:cljs
     (:import [goog.net XhrIo]
              [goog.events EventTarget EventType])
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

(defn sdp [{:sdp/keys [port ip ufrag pwd fingerprint]
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
            :candidate [(str "foundation 1 udp 2130706431 192.168.1.140 " port " typ host")]
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
           ([acc {:rtc/keys [peer channel-name]
                  :as x}]
            (when-not @channel
              (vreset! channel (.createDataChannel peer channel-name)))
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
          (map (fn [{:event/keys [target]
                     :rtc/keys [channel]
                     :as x}]
                 (.info js/console "open" (-> channel))
                 x))))
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
        ;; form handler
        (html/listen-rf
         (dom/getElement "submit")
         :click
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
                         :event/type (get html/net-events :complete))))
           (map (fn [{:net/keys [xhr uri method content headers]
                      :event/keys [type]
                      :as x}]
                  (.info js/console "requesting " uri " " type)
                  (.send xhr uri (name method)
                         (-> content (clj->js) (JSON/stringify))
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
        (map (fn [{:http/keys [json]
                   :ssl/keys [cert]
                   {:cert/keys [fingerprint]} :ssl/cert
                   :as x}]
               (assoc x
                      :context/bip-size (* 20 4096)
                      :ssl/packet-size 1024
                      :ssl/mode :server
                      :ssl/certs [cert]
                      :sdp/fingerprint fingerprint
                      :stun/password "1234567890123456789012"
                      :stun/ufrag "abcd"
                      ;;:http/local-port 2230
                      :context/remote-password (->> json :sdp :sdp (parse-sdp) :a
                                                    :ice-pwd (first)))))
        ;; UDP port
        (rf/one-rf :http/local-port
                   (comp
                    (ice/data-channel-rf (comp
                                          (rf/one-rf :context/buf (comp
                                                                   (map (fn [x]
                                                                          (assoc x :context/buf (ByteBuffer/allocate 150))))
                                                                   (map :context/buf)))
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
        (map (fn [{:context/keys [client]
                   ;;:stun/keys [fingerprint]
                   :http/keys [local-port]
                   :as x}]
               (assoc x
                      ;;:sdp/fingerprint fingerprint
                      :sdp/port local-port)))
        ;; create SDP answer
        (comp
         nio/writable-rf
         (nio/send-rf (comp
                       (map (fn [x]
                              (assoc x :http/json {:type "answer" :sdp (sdp x)})))
                       (rf/debug-rf ::json)
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
                      :event/type (get html/net-events :complete))))
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
                                                      [:pre (JSON/stringify json)]])))
                           html/render-rf)))
       :clj
       (comp rf/identity-rf)))))

#_(

   *e
   *ns*
   (require 'jaq.http.xrf.signaling :reload)
   (in-ns 'jaq.http.xrf.signaling)

   (+ 1 1)
   (-> y :nio/selection-key)
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

   (-> x :rtc/channel (.-id))
   (-> x :rtc/channel (.-label))
   (-> x :rtc/channel (.send "foo"))

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
   (-> (dom/getDocument) (.querySelector "button") (goog.events/removeAll))

   )

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
