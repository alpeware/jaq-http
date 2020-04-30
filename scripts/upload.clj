(ns upload
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [clojure.java.io :as io]
   [jaq.gcp.auth :as auth]
   [jaq.gcp.storage :as storage]
   [jaq.http.xrf.bip :as bip]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.rf :as rf]))

(defn upload-rf [{:storage/keys [bucket]
                  :file/keys [prefix dir]}]
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
                  (assoc :http/params {:bucket bucket}
                         :http/host storage/root
                         :file/prefix prefix
                         :file/dir dir
                         :storage/bucket bucket))))
       (nio/channel-rf
        (comp
         nio/ssl-connection
         (storage/files-rf
          (comp
           ;; one file
           (comp
            storage/file-rf
            storage/session-rf
            storage/rest-service-rf)
           ;; upload url location
           (ssl/request-ssl-rf http/http-rf)
           (ssl/receive-ssl-rf nio/json-response)
           (fn [rf]
             (let [upload-id (volatile! nil)]
               (fn
                 ([] (rf))
                 ([acc] (rf acc))
                 ([acc {:storage/keys [objects bucket]
                        :http/keys [body query-params]
                        :keys [status headers]
                        {:keys [location]} :headers
                        :context/keys [parsed! done!]
                        :as x}]
                  (when-not @upload-id
                    (prn ::location location)
                    (vreset! upload-id (-> location (string/split #"=") (last))))
                  (-> x
                      (dissoc :http/body)
                      (dissoc :http/chunks)
                      (assoc-in [:http/params :bucket] bucket)
                      (assoc-in [:http/query-params :upload-id] @upload-id)
                      (->> (rf acc)))))))

           ;; read file into memory
           (comp
            storage/open-rf
            storage/read-rf
            storage/flip-rf
            storage/close-rf)

           ;; upload chunks of a file
           (comp
            (storage/chunks-rf
             (comp
              storage/rest-service-rf
              (ssl/request-ssl-rf http/http-rf)
              (ssl/receive-ssl-rf nio/json-response)))
            (drop-while (fn [{{:keys [range]} :headers
                              :keys [status]
                              :file/keys [size]
                              :as x}]
                          (prn size status (:headers x))
                          (= status 308))))))
         (drop-while (fn [{{:keys [range]} :headers
                           :keys [status]
                           :file/keys [path size]
                           :as x}]
                       (prn path size)
                       path))
         nio/close-connection))))
     nio/close-rf))))

(defn -main [& [version dir]]
  (let [dir (or dir "./target")]
    (prn ::uploading dir version)
    (->> [{:context/bip-size (* 5 4096)
           :http/scheme :https
           :http/port 443
           :http/method :GET
           :http/minor 1 :http/major 1}]
         (into []
               (upload-rf {:file/prefix (str "app/" version)
                           :file/dir dir
                           :storage/bucket "staging.alpeware-foo-bar.appspot.com"})))))
