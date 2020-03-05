(ns jaq.gcp.auth
  (:require
   [clojure.edn :as edn]
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.json :as json]
   [taoensso.tufte :as tufte :refer [defnp fnp]]))

;; google oauth2
(def google-client-id "32555940559.apps.googleusercontent.com")
(def google-client-secret "ZmssLNjJy2998hD4CTg2ejr2")
(def auth-uri "https://accounts.google.com/o/oauth2/auth")
(def token-uri "https://accounts.google.com/o/oauth2/token")
(def revoke-uri "https://accounts.google.com/o/oauth2/revoke")
(def local-redirect-uri "urn:ietf:wg:oauth:2.0:oob")
(def cloud-scopes ["https://www.googleapis.com/auth/appengine.admin" "https://www.googleapis.com/auth/cloud-platform"])

(def credentials ".credentials.edn")

#_(

   (->> credentials
        (slurp)
        (edn/read-string))
   )

(def google-oauth2
  {:client-id google-client-id
   :client-secret google-client-secret
   :redirect-uri local-redirect-uri
   :token-uri token-uri
   :grant-type "authorization_code"
   })

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

#_(
   (into [] credentials-rf [{:oauth2/client-id :foo :http/params {:foo :bar}}])
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

(defn refresh-token [{:keys [code grant-type]
                      :as params}]
  (->> {:http/host "accounts.google.com" :http/path "/o/oauth2/token"
        :http/method :POST :scheme :https :http/port 443
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
                       (update x :http/req into)
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

;; TODO: extract chunked rf
(def credentials-rf
  (comp
   rf/index
   header/response-line
   header/headers
   (drop 1)
   (fn [rf]
     (let [vacc (volatile! [])
           done (volatile! false)
           val (volatile! nil)
           k :content-length
           assoc-fn (fn [acc x]
                      (->> @val
                           (update x :headers conj)
                           (rf acc)))]
       (fn chunk
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [char]
                {:keys [transfer-encoding]} :headers
                :as x}]
          (if (= "chunked" transfer-encoding)
            (cond
              @done
              (assoc-fn acc x)

              (and
               (nil? @val)
               (contains? #{\return \newline} char))
              (do
                (vreset! val
                         {k
                          (-> (apply str @vacc)
                              (Integer/parseInt 16))})
                (vreset! vacc nil)
                (vreset! done true)
                (rf acc))

              :else
              (do
                (vswap! vacc conj char)
                (rf acc)))
            (rf acc x))))))
   (drop 1)
   (json/decoder)
   (json/process)
   (take 1)
   (map (fn [{:keys [json] :as e}]
          (let [normalize (fn [k] (-> k (name) (string/replace #"_" "-") (keyword)))
                f (fn [[k v]] (if (keyword? k) [(normalize k) v] [k v]))]
            (->> json
                 (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)))
                 (assoc e :json)))))
   (map (fn [{{:keys [expires-in]} :json
              :as e}]
          (->> expires-in
               (* 1000)
               (+ (System/currentTimeMillis))
               (assoc-in e [:json :expires-in]))))))


#_(

   (->>
    (sequence
     (comp
      credentials-rf
      #_(map (fn [{:keys [json] :as e}]
               (let [normalize (fn [k] (-> k (name) (string/replace #"_" "-") (keyword)))
                     f (fn [[k v]] (if (keyword? k) [(normalize k) v] [k v]))]
                 (->> json
                      (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)))
                      (assoc e :json)))))
      #_(map (fn [{{:keys [expires-in]} :json
                   :as e}]
               (->> expires-in
                    (* 1000)
                    (+ (System/currentTimeMillis))
                    (assoc-in e [:json :expires-in])))))
     jaq.http.client.nio/r)
    (first)
    :json)
   (def c *1)

   google-oauth2


   (let [m {:foo_bar :bar}
         normalize (fn [k] (-> k (name) (string/replace #"_" "-") (keyword)))
         f (fn [[k v]] (if (keyword? k) [(normalize k) v] [k v]))]
     (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)) m))
   )


#_(
   (require 'jaq.gcp.auth)
   (in-ns 'jaq.gcp.auth)

   *ns*
   *e
   (exchange-token google-oauth2)
   )
