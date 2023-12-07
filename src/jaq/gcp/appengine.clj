(ns jaq.gcp.appengine
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [clojure.java.io :as io]
   [jaq.gcp.common :as common]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.json :as json]))

(def service-name "appengine.googleapis.com")
(def root-url "appengine.googleapis.com")
(def version "v1beta")
(def service-path [version])

;; TODO: think about it
(def rest-service-rf
  (comp
   (fn [rf]
     (fn
       ([] (rf))
       ([acc] (rf acc))
       ([acc x]
        (->> (assoc x
                    :rest/root-url root-url
                    :rest/service-path service-path)
             (rf acc)))))
   common/rest-rf
   common/auth-rf))

#_(
   (in-ns 'jaq.gcp.appengine)
   (into [] rest-service-rf [{}])
   )

(def app-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [project] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps project]
                   :http/params (dissoc params :project))
            (rf acc))))))

#_(
   (into [] (comp
             service-rf
             app-rf
             rest-rf)
         [{:http/params {:project :project}}])
   )

(def list-operations-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :operations]
                   :http/params (dissoc params :app))
            (rf acc))))))

(def operation-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app id name] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path (if name [name] [:apps app :operations id])
                   :http/params (dissoc params :app  :id :name))
            (rf acc))))))

#_(
   (in-ns 'jaq.gcp.appengine)
   (into [] (comp
             operation-rf
             rest-service-rf)
         [{:http/params {:app :app :id :id}}])
   (into [] (comp
             operation-rf
             rest-service-rf)
         [{:http/params {:name :name}}])
   )

(def list-locations-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :locations]
                   :http/params (dissoc params :app))
            (rf acc))))))

(def list-services-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app] :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :services]
                   :http/params (dissoc params :app))
            (rf acc))))))

(def list-versions-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app service]
              :or {service :default} :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :services service :versions]
                   :http/params (dissoc params :app :service))
            (rf acc))))))

(def list-instances-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app service version]
              :or {service :default} :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :services service :versions version :instances]
                   :http/params (dissoc params :app :service :version))
            (rf acc))))))

#_(
   (in-ns 'jaq.gcp.appengine)
   )

(def instance-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app service version id]
              :or {service :default} :as params} :http/params
             :as x}]
       (->> (assoc x
                   :rest/path [:apps app :services service :versions version :instances id]
                   :http/params (dissoc params :app :service :version :id))
            (rf acc))))))

(def create-version-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [app service]
              :or {service :default} :as params} :http/params
             :http/keys [headers]
             :as x}]
       (->> (assoc x
                   :http/headers (assoc headers :content-type :json)
                   :http/params (dissoc params :app :service)
                   :rest/method :POST
                   :rest/path [:apps app :services service :versions])
            (rf acc))))))

(def default-version
  {:id "v1"
   :runtime "java11"
   ;;:threadsafe true
   :env "standard"
   :automaticScaling {:maxConcurrentRequests 80
                      ;;:maxIdleInstances 1
                      :maxPendingLatency "15s"
                      ;;:minIdleInstances 0
                      :minPendingLatency "10s"
                      :standardSchedulerSettings {:targetCpuUtilization 0.95
                                                  :targetThroughputUtilization 0.95
                                                  ;;:minInstances 0
                                                  :maxInstances 1}}})

;; TODO: static file handlers
(def handlers
  [{:urlRegex "/out/(.*)"
    :securityLevel "SECURE_ALWAYS"
    :staticFiles {:path "/out/\\1"
                  :uploadPathRegex "out/.*"
                  :requireMatchingFile true
                  :applicationReadable true}}
   {:urlRegex "/.*"
    :securityLevel "SECURE_ALWAYS"
    :script {:scriptPath "auto"}}])


(def entrypoint
  {:shell (->> ["java"
                #_"-agentpath:/opt/cprof/profiler_java_agent.so=-logtostderr,-cprof_heap_sampling_interval=262144"
                "-cp classes:clojure-1.10.1.jar:spec.alpha-0.2.176.jar:core.specs.alpha-0.2.44.jar:asm-all-4.2.jar:fressian-0.6.6.jar:fress-0.3.1.jar"
                #_"jaq.http.server"
                "fpp.server"]
               (string/join " "))})

(def env
  {}
  #_{:GAE_PROFILER_MODE "cpu,heap"
   :PROFILER_ENABLE "true"}
  #_(->> (System/getenv)
         (into {})
         (walk/keywordize-keys)))

(defn deployment [bucket prefix items]
  {:files
   (->> items
        (filter (fn [f]
                  (not (string/ends-with? (:name f) "/"))))
        (map (fn [f]
               (let [path (:name f)
                     file-name (string/replace path (str prefix "/") "")
                     url (str "https://storage.googleapis.com/" bucket "/" path)]
                 {file-name {:sourceUrl url}})))
        (into {}))})

(defn version [id bucket prefix items]
  (-> default-version
      (assoc :id id
             :handlers handlers
             :entrypoint entrypoint
             :envVariables env
             :deployment (deployment bucket prefix items))))

(def version-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:storage/keys [bucket prefix objects]
             :appengine/keys [id app service]
             :as x}]
       (->> (assoc x
                   :http/body (-> (version id bucket prefix objects)
                                  (clojure.data.json/write-str)))
            (rf acc))))))

#_(
   (into [] (comp
             version-rf
             (map :http/body))
         [jaq.http.xrf.nio/x])
   )

#_(
   (in-ns 'jaq.gcp.appengine)
   *e
   (def items (-> jaq.http.xrf.nio/x :http/json :items))

   (->> items
        (take 10)
        (version :v2 "staging.alpeware-foo-bar.appspot.com" "target")
        #_(deployment "staging.alpeware-foo-bar.appspot.com" "target"))

   (->> items (take 1))

   *ns*
   ;; TODO: add metadata rfs
   (-> "http://metadata.google.internal/computeMetadata/v1beta1/instance?recursive=true"
       (slurp)
       (clojure.data.json/read-str :key-fn keyword)
       :serviceAccounts
       (vals)
       (first)
       :email
       ((fn [email]
          (str "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/" email "/token")))
       (slurp)
       (clojure.data.json/read-str :key-fn keyword)
       ((fn [{:keys [access_token expires_in]}]
          {:oauth2/access-token access_token
           :oauth2/expires-in (->> expires_in
                                   (* 1000)
                                   (+ (System/currentTimeMillis)))})))

   *e

   (-> (str "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/" email "/token")
       (slurp)
       (clojure.data.json/read-str :key-fn keyword))


   )

#_(def insert-bucket-rf
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

#_(defn app [project-id]
    (action :get [:apps project-id]))

#_(defn create [project-id location-id]
    (action :post [:apps] {:content-type :json
                           :body (json/write-str {"id" project-id
                                                  "locationId" location-id})}))

#_(defn services [app-id]
    (action :get [:apps app-id :services]))
