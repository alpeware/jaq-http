(ns jaq.http.xrf.upnp
  "Universal Plug and Play (UPnP) implementation.

  Focus is on opening ports on routers during development.

  Helpful resources:
  - https://tools.ietf.org/html/draft-cai-ssdp-v1-03
  - https://github.com/adolfintel/WaifUPnP
  - https://www.electricmonk.nl/log/2016/07/05/exploring-upnp-with-python/
  "
  (:require
   [clojure.string :as string]
   [clojure.xml :as xml]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]))

;; TODO: add config-rf
(def user-agent "alpeware")
(def host "239.255.255.250")
(def port 1900)
(def types [
            ;;"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
            ;;"urn:schemas-upnp-org:service:WANIPConnection:1"
            ;;"urn:schemas-upnp-org:service:WANPPPConnection:1"
            "ssdp:all"
            ;;"upnp:rootdevice"
            ])
;; TODO: use http-rf
(def search (->> types
                 (map (fn [e]
                        (str "M-SEARCH * HTTP/1.1\r\n"
                             "HOST: " host ":" port "\r\n"
                             "ST: " e "\r\n"
                             "MAN: \"ssdp:discover\"\r\n"
                             "USER-AGENT: " user-agent "\r\n"
                             "MX: 2\r\n\r\n")))))

;; TODO: extract search req
;; TODO: add xf
(def discover-rf
  (comp
   (nio/datagram-channel-rf
    (comp
     nio/datagram-read-rf
     nio/datagram-write-rf
     (nio/datagram-send-rf
      (comp
       (map
        (fn [{:http/keys [host port] :as x}]
          (assoc x :http/req search)))))
     (rf/repeatedly-rf
      (nio/datagram-receive-rf
       (comp
        (map (fn [{:keys [byte] :as x}]
               (assoc x :char (char byte))))
        header/response-line
        header/headers
        (take 1)
        (map (fn [{:keys [headers char]
                   {:keys [location usn st]} :headers
                   :as x}]
               (assoc x
                      :upnp/gateway headers
                      :upnp/location location
                      :upnp/usn usn
                      :upnp/st st))))))))))

;; TODO: fix
#_(def services-rf
    (comp
     (map (fn [{:upnp/keys [location] :as x}]
            (assoc x
                   :upnp/services
                   (->> locations
                        (map (fn [uri]
                               (try
                                 [(let [[scheme base] (-> location (string/split #"://"))]
                                    (-> base
                                        (string/split #"/")
                                        (first)
                                        (->> (str scheme "://"))))
                                  (xml/parse uri)]
                                 (catch Exception e
                                   nil))))
                        (mapcat (fn [[uri doc]]
                                  (let [uri (or (->> (xml-seq doc)
                                                     (filter (fn [x] (= :URLBase (:tag x))))
                                                     (map :content)
                                                     (first)
                                                     (first))
                                                uri)]
                                    (->> (xml-seq doc)
                                         (filter (fn [x] (= :service (:tag x))))
                                         (map (fn [{:keys [content]}]
                                                (->> content
                                                     (map (fn [node]
                                                            [(:tag node) (-> node :content first)]))
                                                     (into {:uri uri}))))))))))))))

;; TODO: fix
#_(def scp-rf
    (comp
     (map (fn [{:upnp/keys [services] :as x}]
            (assoc x
                   :upnp/scp
                   (->> services
                        (map (fn [{:keys [uri SCPDURL] :as service}]
                               (try
                                 [service
                                  (xml/parse (str uri SCPDURL))]
                                 (catch Exception e
                                   nil))))
                        (map (fn [[service doc]]
                               {:service service
                                :actions
                                (->> (xml-seq doc)
                                     (filter (fn [x] (= :action (:tag x))))
                                     (map (fn [{:keys [content]}]
                                            (->> content
                                                 (map (fn [{:keys [tag content] :as node}]
                                                        (cond
                                                          (= tag :name)
                                                          [tag (first content)]
                                                          (= tag :argumentList)
                                                          [tag (->> content (map (fn [{:keys [content]}]
                                                                                   (->> content
                                                                                        (map (fn [node]
                                                                                               [(:tag node)
                                                                                                (-> node :content first)]))
                                                                                        (into {})))))])))
                                                 (into {})))))
                                :state
                                (->> (xml-seq doc)
                                     (filter (fn [x] (= :stateVariable (:tag x))))
                                     (map (fn [{:keys [content]}]
                                            (->> content
                                                 (map (fn [{:keys [tag content] :as node}]
                                                        (cond
                                                          (contains? #{:name :dataType :defaultValue} tag)
                                                          [tag (first content)]
                                                          (= tag :allowedValueList)
                                                          [tag (->> content (map (fn [node]
                                                                                   (-> node :content first)))
                                                                    #_(into {}))])))
                                                 (into {})))))}))))))))

(def soap-action-rf
  (comp
   (nio/channel-rf
    (comp
     nio/read-rf
     nio/write-rf
     (nio/send-rf (comp
                   (map
                    (fn [{:http/keys [host port]
                          :soap/keys [body service-type action]
                          :as x}]
                      (assoc x
                             :http/headers {:SOAPAction (str service-type "#" action)
                                            :content-type "text/xml"}
                             :http/body body)))
                   http/http-rf))
     #_(rf/debug-rf ::sent)
     nio/readable-rf
     (nio/receive-rf (comp
                      (map (fn [{:keys [byte] :as x}]
                             (assoc x :char (char byte))))
                      header/response-line
                      header/headers
                      http/chunked-rf
                      http/text-rf
                      nio/body-rf
                      (map (fn [{:http/keys [body]
                                 :keys [status reason headers]
                                 :as x}]
                             (prn status reason headers)
                             (prn body)
                             x))))
     nio/close-connection))))

#_(
   (require 'jaq.http.xrf.upnp :reload)
   (in-ns 'jaq.http.xrf.upnp)
   *e
   ;; uPnP
   (let [host "239.255.255.250"
         port 1900
         types [
                ;;"urn:schemas-upnp-org:device:InternetGatewayDevice:1"
                ;;"urn:schemas-upnp-org:service:WANIPConnection:1"
                ;;"urn:schemas-upnp-org:service:WANPPPConnection:1"
                "ssdp:all"
                ;;"upnp:rootdevice"
                ]
         search (->> types
                     (map (fn [e]
                            (str "M-SEARCH * HTTP/1.1\r\n"
                                 "HOST: " host ":" port "\r\n"
                                 "ST: " e "\r\n"
                                 "MAN: \"ssdp:discover\"\r\n"
                                 "USER-AGENT: alpeware\r\n"
                                 "MX: 2\r\n\r\n"))))
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/datagram-channel-rf
                  (comp
                   (rf/debug-rf ::channel)
                   nio/datagram-read-rf
                   (map (fn [{:nio/keys [address] :as x}]
                          (if address
                            (assoc x
                                   :http/host (.getHostName address)
                                   :http/port (.getPort address))
                            x)))
                   nio/datagram-write-rf
                   (nio/datagram-send-rf (comp
                                          (map
                                           (fn [{:http/keys [host port]
                                                 :nio/keys [selection-key]
                                                 :as x}]
                                             (prn ::search search)
                                             (assoc x :http/req search)))))
                   (rf/debug-rf ::sent)
                   (rf/repeatedly-rf
                    (nio/datagram-receive-rf (comp
                                              (map (fn [{:keys [byte] :as x}]
                                                     (assoc x :char (char byte))))
                                              header/response-line
                                              header/headers
                                              #_(map (fn [{:keys [headers char] :as x}]
                                                       (prn char headers)
                                                       x))
                                              (take 1)
                                              (map (fn [{:context/keys [devices]
                                                         :keys [headers char]
                                                         {:keys [location usn st]} :headers
                                                         :as x}]
                                                     (vswap! devices conj headers)
                                                     (prn st usn location)
                                                     x))
                                              #_(drop-while (fn [{:keys [char]}]
                                                              true
                                                              #_(not= char \n)))
                                              #_(fn [rf]
                                                  (let [val (volatile! nil)
                                                        vacc (volatile! nil)]
                                                    (fn
                                                      ([] (rf))
                                                      ([acc] (rf acc))
                                                      ([acc {:keys [char] :as x}]
                                                       (vswap! vacc conj char)
                                                       (cond
                                                         @val
                                                         (->> (assoc x :upnp/gateway @val)
                                                              (rf acc))

                                                         (not= char \n)
                                                         (do
                                                           (vswap! vacc conj char)
                                                           acc)))))))))))
                 nio/writable-rf))
               nio/close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :context/devices (volatile! nil)
            :context/search search
            :http/host host
            :http/port port
            ;;:http/local-port 2222
            ;;:http/local-host "192.168.1.140"
            ;;:http/local-host "172.17.0.2"
            }]
          (into [] xf)))
   (def x (first *1))
   *1
   *e

   (->> x :async/thread (.getState))
   (->> x :nio/selector (.keys))
   (->> x :nio/selector (.keys) (map (fn [e]
                                       (-> e (.channel) (.close))
                                       (.cancel e))))
   (-> x :nio/selector (.wakeup))

   (require 'clojure.pprint)
   (->> x :context/devices (deref) (clojure.pprint/pprint))

   (->> x :context/devices (deref))
   (->> x :context/devices (deref) (map :usn) (set))
   (->> x :context/devices (deref) (map :st) (set))
   (->> x :context/devices (deref) (map :location) (set))
   *e
   (-> x :async/thread (.stop))
   (-> x :async/thread (.getState))
   (-> x :nio/selector (.close))

   (let [locations (->> x :context/devices (deref) (map :location) (set))]
     (->> locations
          (map (fn [uri]
                 (try
                   [(let [[scheme base] (-> uri (string/split #"://"))]
                      (-> base
                          (string/split #"/")
                          (first)
                          (->> (str scheme "://"))))
                    (clojure.xml/parse uri)]
                   (catch Exception e
                     nil))))
          (mapcat (fn [[uri doc]]
                    (let [uri (or (->> (xml-seq doc)
                                       (filter (fn [x] (= :URLBase (:tag x))))
                                       (map :content)
                                       (first)
                                       (first))
                                  uri)]
                      (->> (xml-seq doc)
                           (filter (fn [x] (= :service (:tag x))))
                           (map (fn [{:keys [content]}]
                                  (->> content
                                       (map (fn [node]
                                              [(:tag node) (-> node :content first)]))
                                       (into {:uri uri}))))))))))
   (def services *1)
   (count services)
   (->> services (map :serviceType))
   (last services)

   (->> services
        (filter (fn [{:keys [serviceType]}]
                    (re-matches #"(?i).*:(wanipconnection|wanpppconnection):.*"
                                serviceType)))
        (map (fn [{:keys [uri SCPDURL] :as service}]
               (try
                 [service
                  (clojure.xml/parse (str uri SCPDURL))]
                 (catch Exception e
                   nil))))
        (map (fn [[service doc]]
               {:service service
                :actions
                (->> (xml-seq doc)
                     (filter (fn [x] (= :action (:tag x))))
                     (map (fn [{:keys [content]}]
                            (->> content
                                 (map (fn [{:keys [tag content] :as node}]
                                        (cond
                                          (= tag :name)
                                          [tag (first content)]
                                          (= tag :argumentList)
                                          [tag (->> content (map (fn [{:keys [content]}]
                                                                   (->> content
                                                                        (map (fn [node]
                                                                               [(:tag node)
                                                                                (-> node :content first)]))
                                                                        (into {})))))])))
                                 (into {})))))
                :state
                (->> (xml-seq doc)
                     (filter (fn [x] (= :stateVariable (:tag x))))
                     (map (fn [{:keys [content]}]
                            (->> content
                                 (map (fn [{:keys [tag content] :as node}]
                                        (cond
                                          (contains? #{:name :dataType :defaultValue} tag)
                                          [tag (first content)]
                                          (= tag :allowedValueList)
                                          [tag (->> content (map (fn [node]
                                                                   (-> node :content first)))
                                                    #_(into {}))])))
                                 (into {})))))})))
   (def scp *1)
   (->> scp first :actions (map :name))

   (->> scp
        (filter (fn [{:keys [service]}]
                  (->> service
                       :serviceType
                       (re-matches #"(?i).*:(wanipconnection|wanpppconnection):.*"))))
        (mapcat (fn [{:keys [service actions state]}]
                  (->> actions (filter (fn [{:keys [name]}] (= name "GetExternalIPAddress")))))))

   ;; SOAP request body
   (let [service (->> services (filter (fn [{:keys [serviceType]}]
                                         (string/includes? serviceType "WANIP")))
                      (first))
         service-type (:serviceType service)
         action #_"GetExternalIPAddress" "AddPortMapping" #_"GetSpecificPortMappingEntry" #_"GetGenericPortMappingEntry"
         args #_{} #_{:NewPortMappingIndex "0"} #_{:NewRemoteHost "" :NewProtocol "UDP"
                                                 :NewExternalPort "60000"} #_{:NewRemoteHost "" :NewProtocol "TCP" :NewExternalPort "8080"
                                                                             :NewInternalClient "192.168.1.140" :NewInternalPort "8080"
                                                                             :NewEnabled "1" :NewPortMappingDescription "alpeware"
                                                                            :NewLeaseDuration "0"}
         {:NewRemoteHost "" :NewProtocol "UDP" :NewExternalPort "60000"
          :NewInternalClient "192.168.1.140" :NewInternalPort "60000"
          :NewEnabled "1" :NewPortMappingDescription "stun"
          :NewLeaseDuration "0"}
         soap (->> {:tag :SOAP-ENV:Envelope :attrs {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope"
                                                    :SOAP-ENV:encodingStyle "http://schemas.xmlsoap.org/soap/encoding/"}
                    :content [{:tag :SOAP-ENV:Body
                               :content [{:tag (str "m:" action) :attrs {"xmlns:m" service-type}
                                          :content (->> args (map (fn [[k v]]
                                                                    {:tag k :content [v]})))}]}]}
                   (clojure.xml/emit)
                   (with-out-str))
         soap (string/replace soap "\n" "")
         path (-> service :controlURL)
         [host port] (-> service :uri (string/replace "http://" "") (string/split #":"))
         port (Integer/parseInt port)
         xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/channel-rf
                  (comp
                   nio/read-rf
                   nio/write-rf
                   (nio/send-rf (comp
                             (map
                              (fn [{:http/keys [host port] :as x}]
                                (prn soap)
                                (assoc x
                                       :http/headers {:SOAPAction (str service-type "#" action)
                                                      :content-type "text/xml"}
                                       :http/body soap)))
                             http/http-rf))
                   #_(rf/debug-rf ::sent)
                   nio/readable-rf
                   (nio/receive-rf (comp
                                (map (fn [{:keys [byte] :as x}]
                                       (assoc x :char (char byte))))
                                header/response-line
                                header/headers
                                http/chunked-rf
                                http/text-rf
                                nio/body-rf
                                (map (fn [{:http/keys [body]
                                           :keys [status reason headers]
                                           :as x}]
                                       (prn status reason headers)
                                       (prn body)
                                       x))))
                   nio/close-connection))))
               nio/close-rf)))]
     (->> [{:context/bip-size (* 1 4096)
            :http/scheme :http
            :http/path path
            :http/port port
            :http/host host
            :http/method :POST
            :http/minor 1 :http/major 1}]
          (into [] xf)))
   (def x (first *1))

   x
   *e

   )
