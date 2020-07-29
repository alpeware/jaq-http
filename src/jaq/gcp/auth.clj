(ns jaq.gcp.auth
  (:require
   [clojure.edn :as edn]
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.json :as json]))

;; google oauth2
(def oauth2-host "accounts.google.com")
(def auth-path "/o/oauth2/auth")
(def token-path "/o/oauth2/token")

(def google-client-id "32555940559.apps.googleusercontent.com")
(def google-client-secret "ZmssLNjJy2998hD4CTg2ejr2")
(def auth-uri "https://accounts.google.com/o/oauth2/auth")
(def token-uri "https://accounts.google.com/o/oauth2/token")
(def revoke-uri "https://accounts.google.com/o/oauth2/revoke")
(def local-redirect-uri "urn:ietf:wg:oauth:2.0:oob")
(def cloud-scopes ["https://www.googleapis.com/auth/appengine.admin" "https://www.googleapis.com/auth/cloud-platform"])

(def credentials ".credentials.edn")

#_(
   (require 'jaq.gcp.auth)
   (in-ns 'jaq.gcp.auth)
   *ns*
   (->> credentials
        (slurp)
        (edn/read-string))
   )

(def google-oauth2
  {:client-id google-client-id
   :client-secret google-client-secret
   :redirect-uri local-redirect-uri
   :token-uri token-uri
   :grant-type "authorization_code"})

(def auth-params
  {:access-type "offline"
   :prompt "consent"
   :include-granted-scopes "true"
   :response-type "code"
   :scope (string/join " " cloud-scopes)})

(def auth-url
  (comp
   (map (fn [x] (assoc x :http/req [])))
   (map (fn [x]
          (assoc x
                 :http/method :GET
                 :http/scheme :https
                 :http/host oauth2-host
                 :http/path auth-path
                 :http/params (-> google-oauth2 (select-keys [:client-id :redirect-uri]) (merge auth-params)))))
   (map (fn [{:http/keys [req scheme host path] :as x}]
          (update x :http/req conj (str (name scheme) "://" host path))))
   http/params-rf
   (map (fn [{:http/keys [req] :as x}]
          (assoc x :http/url (string/join req))))))

#_(

   (in-ns 'jaq.gcp.auth)
   (into [] (comp
             auth-url
             (map :http/url))
         [{:http/req []}])

   )

;; TODO: transducify
(defn exchange-token [{:keys [code grant-type]
                       :as params}]
  (->> {:http/host "accounts.google.com" :http/path "/o/oauth2/token"
        :http/method :POST :http/scheme :https :http/port 443
        :http/minor 1 :http/major 1
        :http/headers {:content-type "application/x-www-form-urlencoded"}
        :http/params params}
       (conj [])
       (sequence
        (comp
         (map (fn [x] (assoc x :http/req [])))
         (map (fn [{:http/keys [req headers host] :as x}]
                (assoc x :http/headers (conj {:Host host} headers))))
         (map (fn [{:http/keys [req method] :as x}]
                (update x :http/req conj (-> method (name) (str)))))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj " ")))
         (map (fn [{:http/keys [req path] :as x}]
                (update x :http/req conj path)))
         (fn [rf]
           (let [normalize (fn [s] (clojure.string/replace s #"-" "_"))]
             (fn params
               ([] (rf))
               ([acc] (rf acc))
               ([acc {:http/keys [req method params] :as x}]
                (if (and (= :GET method) params)
                  (->> params
                       (reduce
                        (fn [reqs [k v]]
                          (conj reqs
                                (->> k (name) (str) (normalize) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                "="
                                (->> v (str) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                "&"))
                        ["?"])
                       (butlast)
                       (update x :req into)
                       (rf acc))
                  (rf acc x))))))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj " ")))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj "HTTP")))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj "/")))
         (map (fn [{:http/keys [req major minor] :as x}]
                (update x :http/req conj (str major "." minor))))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj "\r\n")))
         (fn [rf]
           (let [normalize (fn [s] (clojure.string/replace s #"-" "_"))]
             (fn params
               ([] (rf))
               ([acc] (rf acc))
               ([acc {:http/keys [method params body]
                      :as x}]
                (if (and (= :POST method) params)
                  (->> params
                       (reduce
                        (fn [bodies [k v]]
                          (conj bodies
                                (->> k (name) (str) (normalize) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                "="
                                (->> v (str) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                                "&"))
                        [])
                       (butlast)
                       (clojure.string/join)
                       (assoc x :http/body)
                       (rf acc))
                  (rf acc x))))))
         (map (fn [{:http/keys [headers body] :as x}]
                (update x :http/headers conj {:content-length (count body)})))
         (fn [rf]
           (fn headers
             ([] (rf))
             ([acc] (rf acc))
             ([acc {:http/keys [req headers] :as x}]
              (if headers
                (->> headers
                     (reduce
                      (fn [reqs [k v]]
                        (conj reqs
                              (->> k (name) (str) (string/capitalize))
                              ": "
                              (->>
                               (cond
                                 (instance? clojure.lang.Keyword v)
                                 (name v)
                                 :else
                                 v)
                               (str))
                              "\r\n"))
                      [])
                     (update x :http/req into)
                     (rf acc))
                (rf acc x)))))
         (map (fn [{:http/keys [req] :as x}]
                (update x :http/req conj "\r\n")))
         (map (fn [{:http/keys [req body] :as x}]
                (update x :http/req conj body)))))
       (first)))

#_(
   (in-ns 'jaq.gcp.auth)

   (exchange-token (merge google-oauth2 {:code "4/1wFRLh4XeTTye4sE9K-RPs6hHx6VlhTGEQmm5MO0aCxkYhBESh8uQIA"}))

   (let [xf (comp
             nio/selector-rf
             (nio/thread-rf
              (comp
               (nio/select-rf
                (comp
                 (nio/channel-rf
                  (comp
                   nio/ssl-connection
                   (ssl/request-ssl-rf http/http-rf)
                   (ssl/receive-ssl-rf nio/json-response)
                   (map (fn [{:http/keys [json chunks]
                              :as x}]
                          (assoc x :oauth2/credentials json)))
                   nio/close-connection))
                 (drop-while (fn [{:oauth2/keys [credentials] :as x}]
                               (nil? credentials)))
                 (map (fn [{{:keys [expires-in]} :http/json
                            :as x}]
                        (if expires-in
                          (->> expires-in
                               (* 1000)
                               (+ (System/currentTimeMillis))
                               (assoc-in x [:http/json :expires-in]))
                          x)))
                 (map (fn [{:http/keys [json]
                            :context/keys [request]
                            :as x}]
                        (let [oauth2 (->> json
                                          (map (fn [[k v]]
                                                 [(keyword "oauth2" (name k)) v]))
                                          (into {}))]
                          (prn ::oauth2 oauth2)
                          (merge x oauth2))))
                 store-rf
                 (map (fn [{:oauth2/keys [credentials]
                            :context/keys [store]
                            :as x}]
                        (prn ::credentials credentials)
                        (vreset! store credentials)
                        x))))
               nio/close-rf)))]
     (->> [{:context/bip-size (* 5 4096)
            :context/store (volatile! nil)
            :http/host "accounts.google.com" :http/path "/o/oauth2/token"
            :http/method :POST :http/scheme :https :http/port 443
            :http/minor 1 :http/major 1
            :http/headers {:content-type "application/x-www-form-urlencoded"}
            :http/params (merge google-oauth2 {:code "4/1wGkXe_fHbpr7Ycno_T_AdWTrgzHIEOG0Bi0pWHKET7kF2F6t8P_z9Q"})}]
          (into [] xf)))
   (def x (first *1))

   (-> x :context/store (deref))

   *e


   )

(def credentials-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:oauth2/keys [client-id client-secret refresh-token]
             :as x}]
       (if-not refresh-token
         (->> credentials
              (slurp)
              (edn/read-string)
              (merge x)
              (rf acc))
         (rf acc x))))))

(def store-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:oauth2/keys [expires-in]
             :as x}]
       (when (> expires-in (System/currentTimeMillis))
         (->> x
              (filter (fn [[k v]] (= "oauth2" (namespace k))))
              (into {})
              (prn-str)
              (spit credentials)))
       (rf acc x)))))

#_(
   (in-ns 'jaq.gcp.auth)
   (into [] credentials-rf [{:oauth2/client-id :foo :http/params {:foo :bar}}])

   (->> oauth2
        (prn-str)
        (spit "/opt/jaq-http/.credentials.edn"))
   )

(def refresh-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:http/keys [headers params path host method minor major port]
             :oauth2/keys [client-id client-secret refresh-token]
             :as x}]
       (->> (assoc x
                   :context/request x
                   :http/host "accounts.google.com"
                   :http/path "/o/oauth2/token"
                   :http/params {:grant-type "refresh_token" :client-id client-id
                                 :client-secret client-secret :refresh-token refresh-token}
                   :http/headers {:content-type "application/x-www-form-urlencoded"}
                   :http/method :POST
                   :http/scheme :https
                   :http/port 443
                   :http/minor 1
                   :http/major 1)
            (rf acc))))))

#_(
   (into [] refresh-rf [{}])
   )

#_(
   (in-ns 'jaq.gcp.auth)
   (require 'jaq.gcp.auth)

   (-> (merge
        google-oauth2 token
        {:grant-type "refresh_token"})
       (select-keys
        [:grant-type :client-id :client-secret :refresh-token])
       (refresh-token)
       (select-keys [:http/headers :http/params :http/path :http/host
                     :http/method :http/minor :http/major :http/port]))

   (def c *1)

   )
