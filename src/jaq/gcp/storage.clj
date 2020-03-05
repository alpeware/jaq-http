(ns jaq.gcp.storage
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.json :as json]
   [taoensso.tufte :as tufte :refer [defnp fnp]]))


(def service-name "storage-api.googleapis.com")
(def root-url "storage.googleapis.com")
(def version "v1")
(def service-path [:storage version])

#_(defn buckets [project-id & [{:keys [pageToken maxResults prefix
                                       projection userProject] :as params}]]
    (lazy-seq
     (let [{:keys [items nextPageToken error]} (action
                                                :get [:b]
                                                {:query-params (merge
                                                                {"project" project-id}
                                                                params)})]
       (or
        error
        (concat items
                (when nextPageToken
                  (buckets project-id (assoc params :pageToken nextPageToken))))))))



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

#_(
   (into []
         rest-rf
         [#:rest{:root-url root-url :service-path service-path :path [:b]}])
   (concat [:foo] [:bar])
   )

(def service-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc x]
       (->> (assoc x
                   :rest/root-url root-url
                   :rest/service-path service-path)
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

(def list-buckets-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc x]
       (->> (assoc x :rest/path [:b])
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             list-buckets-rf
             rest-rf
             auth-rf)
         [{:http/params {:project :project}
           :oauth2/access-token :token}])

   *e
   )

#_(defn buckets [{:params/keys [project]
                  :oauth2/keys [access-token]
                  :as x}]
    {:rest/root-url root-url
     :rest/service-path service-path
     :rest/path [:b]
     :http/params {:project project}}
    #_(->> {:http/host endpoint
            :http/path (->> [:b]
                            (concat default-endpoint)
                            (map name)
                            (interpose "/")
                            (string/join))
            :http/method :GET :http/scheme :https
            ;; TODO: extract to default-http-rf
            :http/port 443 :http/minor 1 :http/major 1
            ;; TODO: extract to auth-rf
            :http/headers {:Authorization (str "Bearer " access-token)}
            :http/params {:project project}}
           ))

#_(defn new [{:keys [project-id bucket location storage-class]}]
    (action :post [:b] {:query-params {"project" project-id}
                        :content-type :json
                        :body (json/write-str {"name" bucket
                                               "location" location
                                               "storageClass" storage-class})}))

(def insert-bucket-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [project] :as params} :http/params
             {:keys [content-type] :as headers} :http/headers
             :as x}]
       (->> (assoc x
                   :http/headers (assoc headers :content-type :json)
                   :http/body (dissoc params
                                      :project ;; required
                                      :projection
                                      :predefined-acl
                                      :predefined-default-object-acl)
                   :http/method :POST
                   :rest/path [:b])
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             insert-bucket-rf
             rest-rf)
         [{:http/params {:project :project
                         :name :bucket
                         :location :location}}])
   )

(def delete-bucket-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [project bucket] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :http/method :DELETE
                   :http/params (dissoc params :bucket)
                   :rest/path [:b bucket])
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             delete-bucket-rf
             rest-rf)
         [{:http/params {:project :project
                         :bucket "some-bucket"}}])
   )

;; TODO: handle paging / nextPageToken
(def list-objects-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [project bucket] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :http/params (dissoc params :bucket)
                   :rest/path [:b bucket :o])
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             list-objects-rf
             rest-rf
             auth-rf)
         [{:http/params {:project :project :bucket :bucket}
           :oauth2/access-token :token}])

   *e)

#_(defn objects [bucket & [{:keys [prefix pageToken maxResults] :as params}]]
    (lazy-seq
     (let [{:keys [items nextPageToken error]} (action :get
                                                       [:b bucket :o]
                                                       {:query-params params})]
       (or
        error
        (concat items (when nextPageToken
                        (objects bucket (assoc params :pageToken nextPageToken))))))))

(def object-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [project bucket object] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :http/params (-> params
                                    (dissoc :bucket :object)
                                    (assoc :alt "media"))
                   :rest/path [:b bucket :o (java.net.URLEncoder/encode object "UTF-8")])
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             object-rf
             rest-rf
             auth-rf)
         [{:http/params {:project :project :bucket :bucket
                         :object "/foo/bar.baz"}
           :oauth2/access-token :token}])

   (sequence (comp
             rf/index
             (params/encoder)
             (map :char)) "foo/bar.baz" )

   (java.net.URLEncoder/encode "/foo/bar.baz" "UTF-8")
   *e)

#_(defn get-file [bucket file-name]
  (let [file-path (util/url-encode file-name)]
    (action :get [:b bucket :o file-path] {:query-params {:alt "media"}})))

#_(
   (require 'jaq.gcp.storage :reload)
   (in-ns 'jaq.gcp.storage)
   (buckets {:params/project :project-id})
   )
