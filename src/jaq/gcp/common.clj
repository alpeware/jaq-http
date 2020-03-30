(ns jaq.gcp.common
  (:require
   [clojure.string :as string]))

;; see https://developers.google.com/discovery/v1/building-a-client-library
(def rest-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:rest/keys [root-url service-path path
                         method port scheme]
             :or {method :GET port 443 scheme :https}
             :as x}]
       (->> path
            (concat service-path)
            (interpose :/)
            (concat [:/])
            (map name)
            (string/join)
            (assoc x
                   :http/port port
                   :http/scheme scheme
                   :http/method method
                   :http/host root-url
                   :http/path)
            (rf acc))))))

(def auth-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:oauth2/keys [access-token]
             :http/keys [headers]
             :as x}]
       (->> access-token
            (str "Bearer ")
            (assoc headers :Authorization)
            (assoc x :http/headers)
            (rf acc))))))

(defn service-rf [root-url service-path]
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc x]
       (->> (assoc x
                   :rest/root-url root-url
                   :rest/service-path service-path)
            (rf acc))))))

#_(
   (in-ns 'jaq.gcp.common)
   *e
   )
