(ns deploy
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [clojure.java.io :as io]
   [jaq.gcp.auth :as auth]
   [jaq.gcp.appengine :as appengine]
   [jaq.gcp.storage :as storage]
   [jaq.http.xrf.bip :as bip]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.rf :as rf]))

(defn deploy-rf [{:storage/keys [bucket]
                  :appengine/keys [app]
                  :file/keys [prefix]}]
  (comp
   nio/selector-rf
   (nio/thread-rf
    (comp
     (nio/select-rf
      (comp
       nio/auth-chan
       (drop-while (fn [{:oauth2/keys [expires-in]}]
                     (and (not expires-in)
                          (> (System/currentTimeMillis) expires-in))))
       (rf/one-rf :oauth2/access-token (comp
                                        (map :oauth2/access-token)))
       (map (fn [x]
              (-> x
                  (dissoc :http/json :http/body :http/chunks :http/headers :ssl/engine)
                  (assoc :http/params {:bucket bucket
                                       :prefix prefix}
                         :http/host storage/root
                         :storage/prefix prefix
                         :appengine/id (str (System/currentTimeMillis))
                         :appengine/app app
                         :appengine/service :default
                         :storage/bucket bucket))))
       (nio/channel-rf
        (comp
         nio/ssl-connection
         (storage/pages-rf
          (comp
           storage/list-objects-rf
           storage/rest-service-rf
           (ssl/request-ssl-rf http/http-rf)
           (ssl/receive-ssl-rf nio/json-response)))
         (map (fn [{:storage/keys [pages]
                    {:keys [items]} :http/json
                    :as x}]
                #_(prn ::pages pages)
                (prn ::items (count items))
                x))
         (drop-while (fn [{:storage/keys [pages]
                           {:keys [nextPageToken items]} :http/json
                           :as x}]
                       nextPageToken))
         (map (fn [{:storage/keys [pages]
                    {:keys [items]} :http/json
                    :as x}]
                (prn ::pages (count pages))
                x))
         nio/close-connection))
       (drop-while (fn [{:storage/keys [pages] :as x}]
                     (nil? pages)))
       ;; got list of files
       (fn [rf]
         (let [objects (volatile! nil)]
           (fn
             ([] (rf))
             ([acc] (rf acc))
             ([acc {:appengine/keys [app service]
                    :storage/keys [pages bucket]
                    :as x}]
              (when-not @objects
                (->> pages (mapcat :items) (vreset! objects)))
              (-> x
                  (dissoc :http/params :http/headers :http/body
                          :http/req :http/chunks :http/json
                          :ssl/engine)
                  (assoc-in [:http/params :app] app)
                  (assoc-in [:http/params :service] service)
                  (assoc :storage/objects @objects)
                  (assoc :http/host appengine/root-url)
                  (->> (rf acc)))))))
       ;; deploy rest
       (nio/channel-rf
        (comp
         nio/ssl-connection
         (comp
          appengine/version-rf
          appengine/create-version-rf
          appengine/rest-service-rf
          (ssl/request-ssl-rf http/http-rf)
          (ssl/receive-ssl-rf nio/json-response))
         (map (fn [{:storage/keys [pages]
                    {:keys [items] :as json} :http/json
                    :as x}]
                (prn ::json json)
                x))
         nio/close-connection))
       ;; operation
       ;; migrate
       ))
     nio/close-rf))))

(defn -main [& [version dir]]
  (let []
    (prn ::deploying version)
    (->> [{:context/bip-size (* 10 4096)
           :http/scheme :https
           :http/port 443
           :http/method :GET
           :http/minor 1 :http/major 1}]
         (into []
               (deploy-rf {:file/prefix (str "app/" version)
                           :appengine/app "alpeware-foo-bar"
                           :storage/bucket "staging.alpeware-foo-bar.appspot.com"})))))
