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

(defn upload [oauth2]
  (let [selector (nio/selector!)
        xf (comp
             (rf/branch (fn [{:oauth2/keys [expires-in]}]
                          (> (System/currentTimeMillis) expires-in))
                        nio/auth-rf
                        rf/identity-rf)
             nio/attachment-rf
             nio/channel-rf
             ssl/ssl-rf
             nio/process-rf
             ssl/handshake-rf
             storage/files-rf
             #_(map (fn [{:file/keys [path] :as x}]
                      (prn ::path path)
                      x))
             ;; upload one file
             (rf/branch (fn [{:file/keys [path]}]
                          path)
                        (comp
                         (rf/once-rf
                          (comp
                           storage/file-rf
                           storage/session-rf
                           storage/rest-service-rf
                           http/http-rf
                           nio/selector-rf
                           ssl/request-ssl-rf
                           ssl/response-ssl-rf
                           header/response-line
                           header/headers
                           http/parsed-rf
                           http/chunked-rf
                           http/text-rf
                           nio/body-rf
                           (comp
                            (fn [rf]
                              (let [once (volatile! false)]
                                (fn
                                  ([] (rf))
                                  ([acc] (rf acc))
                                  ([acc {:storage/keys [objects bucket]
                                         :http/keys [body query-params]
                                         :keys [status headers]
                                         {:keys [location]} :headers
                                         :context/keys [parsed! done!]
                                         :as x}]
                                   (when-not @once
                                     (prn ::location location status)
                                     (parsed!)
                                     (done!)
                                     (vreset! once true))
                                   #_(prn ::location location)
                                   (-> x
                                       (dissoc :http/body)
                                       (dissoc :http/chunks)
                                       (assoc-in [:http/params :bucket] bucket)
                                       (assoc-in [:http/query-params :upload-id] (-> location (string/split #"=") (last)))
                                       (->> (rf acc)))))))
                            storage/open-rf
                            storage/read-rf
                            storage/flip-rf
                            storage/close-rf
                            storage/upload-rf
                            storage/rest-service-rf
                            http/http-rf
                            (map (fn [{:context/keys [wait! go!] :as x}]
                                   (wait!)
                                   x))
                            ssl/request-ssl-rf
                            ssl/response-ssl-rf
                            (rf/once-rf
                             (comp
                              header/response-line
                              header/headers
                              http/parsed-rf
                              http/chunked-rf
                              http/text-rf
                              nio/body-rf
                              (map (fn [{:context/keys [parsed!] :as x}]
                                     (parsed!)
                                     x))))
                            (drop-while (fn [{{:keys [range]} :headers
                                              :keys [status]
                                              :context/keys [clear! go!]
                                              :file/keys [size]
                                              :as x}]
                                          (prn size status (:headers x))
                                          (go!)
                                          (clear!)
                                          (= status 308)))
                            (map (fn [{:context/keys [wait! next!] :as x}]
                                   (wait!)
                                   (next!)
                                   x))))))
                        rf/identity-rf)
             (drop-while (fn [{:file/keys [path]
                               :keys [status]}]
                           (and (= status 200) path))))
        rf (xf (rf/result-fn))]
    (rf nil
        (merge
         {:nio/selector selector
          :context/bip-size (* 5 4096)
          :file/prefix "app/v4"
          :file/dir "./target"
          :storage/bucket "staging.alpeware-foo-bar.appspot.com"
          :http/params {:bucket "staging.alpeware-foo-bar.appspot.com"}
          :http/host storage/root
          :http/scheme :https
          :http/port 443
          :http/minor 1 :http/major 1}
         oauth2))
    (let [step (partial nio/reactor-main selector)
          start (System/currentTimeMillis)
          ;;timeout (* 60 1000)
          steps (fn []
                  (if-let [r (rf)]
                    r
                    (do
                      (step)
                      (recur))))]
      (steps))))

(defn credentials []
  (->> ".credentials.edn"
       (slurp)
       (clojure.edn/read-string)))

(defn -main [& args]
  (-> (credentials)
      (upload)))
