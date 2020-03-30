(ns jaq.gcp.storage
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [clojure.java.io :as io]
   [jaq.gcp.common :as common]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.json :as json])
  (:import
   [java.nio ByteBuffer ByteOrder]
   [java.nio.file Paths Path FileStore Files FileSystems FileSystem OpenOption]
   [java.nio.channels FileChannel]
   [com.sun.nio.file ExtendedOpenOption]))


(def service-name "storage-api.googleapis.com")
(def root "storage.googleapis.com")
(def version "v1")
(def path [:storage version])

;; The number of bytes uploaded is required to be equal or greater than 262144,
;; except for the final request (it's recommended to be the exact multiple of 262144).
(def default-chunk-size (* 256 1024))

(def rest-service-rf
  (comp
   (fn [rf]
     (fn
       ([] (rf))
       ([acc] (rf acc))
       ([acc {:rest/keys [root-url service-path]
              :or {root-url root service-path path}
              :as x}]
        (->> (assoc x
                    :rest/root-url root-url
                    :rest/service-path service-path)
             (rf acc)))))
   common/rest-rf
   common/auth-rf))

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
             list-buckets-rf
             rest-service-rf)
         [{:http/params {:project :project}
           :oauth2/access-token :token}])

   *e
   )

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
             insert-bucket-rf
             rest-service-rf)
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
      ([acc {{:keys [bucket] :as params} :http/params
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
   (in-ns 'jaq.gcp.storage)
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

(def file-rf
  (fn [rf]
    (let [file-system (FileSystems/getDefault)
          separator (.getSeparator file-system)
          re (re-pattern separator)
          p (volatile! nil)
          ct (volatile! nil)
          s (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [path content-type]
               :as x}]
         (when-not @p
           (prn ::file path)
           (->> (string/split path re)
                ((fn [[a & b]]
                   (.getPath file-system a (into-array String b))))
                (vreset! p))
           (vreset! ct (or content-type (-> @p (Files/probeContentType) ) "application/octet-stream"))
           (vreset! s (-> @p (Files/size))))
         (->> (assoc x
                     :file/p @p
                     :file/content-type @ct
                     :file/size @s)
              (rf acc)))))))

;; see https://events19.linuxfoundation.org/wp-content/uploads/2017/11/Accelerating-IO-in-Big-Data-%E2%80%93-A-Data-Driven-Approach-and-Case-Studies-Yingqi-Lucy-Lu-Intel-Corporation.pdf
(def open-rf
  (fn [rf]
    (let [channel (volatile! nil)
          buf (volatile! nil)
          a (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [p size]
               :as x}]
         (when-not @channel
           (->> (FileChannel/open p (into-array OpenOption [ExtendedOpenOption/DIRECT]))
                (vreset! channel))
           (let [alignment (->> p (Files/getFileStore) (.getBlockSize))
                 capacity (if (< size alignment) (* 2 alignment) (+ size alignment alignment))]
             (vreset! a alignment)
             (-> capacity
                 (ByteBuffer/allocateDirect)
                 (.alignedSlice alignment)
                 (->> (vreset! buf)))))
         (->> (assoc x
                     :file/channel @channel
                     :file/buf @buf
                     :file/alignment @a)
              (rf acc)))))))

(def close-rf
  (fn [rf]
    (let [once (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [^FileChannel channel]
               :as x}]
         (when-not @once
           (.close channel)
           (vreset! once true))
         (rf acc x))))))

(def read-rf
  (fn [rf]
    (let [once (volatile! nil)
          read (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [^FileChannel channel ^ByteBuffer buf]
               :as x}]
         (when-not @read
           (->> (.read channel buf)
                (vreset! read)))
         (->> (assoc x
                     :file/read @read)
              (rf acc)))))))

(def flip-rf
  (fn [rf]
    (let [once (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [^FileChannel channel ^ByteBuffer buf]
               :as x}]
         (when-not @once
           (.flip buf)
           (vreset! once true))
         (rf acc x))))))

(def files-rf
  (fn [rf]
    (let [fs (volatile! nil)
          f (volatile! nil)
          next! (fn []
                  (vreset! f (first @fs))
                  (vswap! fs rest))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:file/keys [dir]
               :as x}]
         (when-not @fs
           (->> dir
                (io/file)
                (file-seq)
                (filter (fn [e] (.isFile e)))
                (vreset! fs))
           (next!))
         (->> (assoc x
                     :context/next! next!
                     :file/path (some-> @f (.getPath)))
              (rf acc)))))))

#_(
   (in-ns 'jaq.gcp.storage)
   (into [] (comp
             files-rf
             (map (fn [{:context/keys [next!] :as x}]
                    (next!)
                    x))
             file-rf
             #_(map :file/path)
             (take 6))
         (repeat {:file/dir "./scripts"}))

   (repeat 5 {:file/dir "."})

   (let [fs (volatile! nil)
         f (fn [] (let [f (first @fs)]
                    (vswap! fs rest)
                    f))]
     (->> "."
          (io/file)
          (file-seq)
          (filter (fn [e] (.isFile e)))
          (vreset! fs))
     [(f) (f)]
     )
   )

#_(
   (in-ns 'jaq.gcp.storage)

   *e
   (into [] (comp
             file-rf
             open-rf
             read-rf
             close-rf)
         [{:file/path "./target/clojure-1.10.1.jar" ;; "./deps.edn"
           :file/dir "."}])
   (def a *1)

   (-> a first :file/channel (.size))
   (-> a first :file/buf (.capacity))

   (let [buf (-> (java.nio.ByteBuffer/allocateDirect (* 2 4096)) (.alignedSlice 4096))
         ch (-> (FileSystems/getDefault)
                (.getPath "." (into-array String ["deps.edn"]))
                (FileChannel/open (into-array OpenOption [ExtendedOpenOption/DIRECT])))
         size (.size ch)]
     (.read ch buf)
     (.close ch)
     (.flip buf)
     (->> buf
          (.decode jaq.http.xrf.params/default-charset)
          (.toString))
     size
     )

   (-> (FileSystems/getDefault)
       (.getPath "." (into-array String ["foo.json"]))
       #_(Files/size)
       (Files/probeContentType))

   (->> java.nio.file.FileSystem
        clojure.reflect/reflect
        #_(map :name)
        clojure.pprint/pprint)


   (->> "./deps.edn"
        (Paths/get))

   (require 'clojure.reflect)
   *e
   )

(def session-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {{:keys [bucket] :as params} :http/params
             :http/keys [headers]
             :file/keys [path dir prefix content-type size]
             :as x}]
       (->> (assoc (dissoc x :http/params)
                   :http/query-params (-> params
                                          (dissoc :bucket)
                                          (assoc :uploadType "resumable"
                                                 :name (string/replace-first path dir prefix)))
                   :http/headers (assoc headers
                                        "X-Upload-Content-Type" content-type
                                        "X-Upload-Content-Length" size
                                        :content-type "application/json")
                   :rest/service-path [:upload :storage version]
                   :rest/method :POST
                   :rest/path [:b bucket :o])
            (rf acc))))))

#_(

   (into [] (comp
             service-rf
             file-rf
             session-rf
             rest-rf
             auth-rf)
         [{:http/params {:bucket :bucket}
           :file/path "./deps.edn"
           :file/dir "."
           :file/prefix "/foo"
           :oauth2/access-token :token}])
   )

#_(defn create-session-uri [{:keys [bucket path base-dir prefix]}]
    (let [file (io/file path)
          content-length (-> file .length str)
          dir base-dir ;; (.getParent file)
          file-name (string/replace-first path dir prefix)
          content-type (or (ext-mime-type path extra-mime-types) "application/octet-stream")]
      (->
       (jaq.services.util/action [endpoint :upload :storage version]
                                 :post [:b bucket :o]
                                 {:headers {"X-Upload-Content-Type" content-type
                                            "X-Upload-Content-Length" content-length}
                                  :content-type :json
                                  :query-params {:uploadType "resumable"
                                                 :name file-name}
                                  :body ""}
                                 true)
       :headers
       walk/keywordize-keys
       :location)))

(def upload-rf
  (fn [rf]
    (let [wait (volatile! false)
          wait! (fn [] (vreset! wait true))
          go! (fn [] (vreset! wait false))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {{:keys [bucket] :as params} :http/params
               :http/keys [headers chunk-size location]
               :file/keys [^FileChannel channel ^ByteBuffer buf size alignment]
               :or {chunk-size default-chunk-size}
               :as x}]
         (if @wait
           (->> (assoc x
                       :context/wait! wait!
                       :context/go! go!)
                (rf acc))
           (let [^ByteBuffer b (-> buf
                                   (.slice)
                                   (as-> e
                                       (if (< (.limit e) chunk-size)
                                         e
                                         (.limit e chunk-size))))
                 index (.position buf)
                 offset (->> b (.remaining) (dec) (+ index))
                 content-range (str "bytes " index "-" offset "/" size)]
             (.position buf (inc offset))
             (prn ::storage content-range (.hasRemaining b) (.hasRemaining buf) b buf)
             (if (.hasRemaining b)
               (->> (assoc (dissoc x :http/params)
                           :context/wait! wait!
                           :context/go! go!
                           :http/headers (assoc headers
                                                "Content-Range" content-range
                                                :content-length (.limit b)
                                                :content-type "application/octet-stream")
                           :http/body b
                           :rest/service-path [:upload :storage version]
                           :rest/method :POST
                           :rest/path [:b bucket :o])
                    (rf acc))
               (->> (assoc x
                           :context/wait! wait!
                           :context/go! go!)
                    (rf acc))))))))))

#_(

   (in-ns 'jaq.gcp.storage)
   *e
   (into [] (comp
             file-rf
             open-rf
             read-rf
             close-rf)
         [{:file/path "./deps.edn"
           :file/dir "."}])

   (into [] (comp
             service-rf
             file-rf
             open-rf
             read-rf
             flip-rf
             close-rf
             upload-rf
             rest-rf
             auth-rf)
         [{:http/params {:bucket :bucket}
           :http/chunk-size 4096
           :file/path "./deps.edn"
           :file/dir "."
           :file/prefix "/foo"
           :oauth2/access-token :token}
          {:http/params {:bucket :bucket}
           :http/chunk-size 4096
           :file/path "./deps.edn"
           :file/dir "."
           :file/prefix "/foo"
           :oauth2/access-token :token}])
   *e

   (let [b (ByteBuffer/allocate 4)]
     (.putChar b \A)
     (.putChar b \B)
     (.flip b)
     (->> ["foo" b]
          (map (fn [e]
                 (cond
                   (string? e)
                   (-> (.getBytes e)
                       (ByteBuffer/wrap))

                   (instance? ByteBuffer e)
                   e)))
          )
     )

   )
#_(defn upload-chunk [{:keys [session-uri path file-size index chunk-size]}]
    (with-open [f (java.io.RandomAccessFile. path "r")]
      (let [buffer (byte-array chunk-size)
            _ (.seek f index)
            bytes-read (.read f buffer)
            file-pointer (-> f .getFilePointer)
            offset (dec file-pointer)
            content-range (str "bytes " index "-" offset "/" file-size)
            resp (->
                  (http/put session-uri {:headers {"Content-Range" content-range}
                                         :content-length (str bytes-read)
                                         :body-encoding "application/octet-stream"
                                         :throw-exceptions false
                                         :body (->> buffer
                                                    (take bytes-read)
                                                    byte-array)})
                  (walk/keywordize-keys))]
        resp)))

#_(
   (require 'jaq.gcp.storage :reload)
   (in-ns 'jaq.gcp.storage)
   (buckets {:params/project :project-id})
   )
