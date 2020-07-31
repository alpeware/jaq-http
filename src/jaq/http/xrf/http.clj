(ns jaq.http.xrf.http
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.nio.channels SelectionKey]
   [java.nio ByteBuffer ByteOrder CharBuffer]))

(def parsed-rf
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:context/keys [parsed!]
               :nio/keys [^SelectionKey selection-key]
               :keys [char]
               :as x}]
         (if-not @once
           (do
             #_(prn ::parsed x)
             #_(.interestOps selection-key SelectionKey/OP_READ)
             (parsed!)
             (vreset! once true)
             (->> char (byte) (assoc x :byte) (rf acc)))
           (rf acc x)))))))

(def chunked-rf
  (fn [rf]
    (let [vacc (volatile! [])
          done (volatile! false)
          val (volatile! nil)
          chunked! (fn []
                     (prn ::chunked!)
                     (vreset! done false)
                     (vreset! val nil))
          k :content-length
          assoc-fn (fn [acc x]
                     (->> @val
                          (update x :headers conj)
                          ((fn [e] (assoc e :context/chunked! chunked!)))
                          (rf acc)))]
      (fn chunk
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [byte]
               {:keys [transfer-encoding]} :headers
               :as x}]
         (if (= "chunked" transfer-encoding)
           (cond
             @done
             (assoc-fn acc x)

             (and
              (empty? @vacc)
              (nil? @val)
              (contains? #{10 13} byte))
             acc

             (and
              @val
              (contains? #{10 13} byte))
             (do
               (vreset! done true)
               acc)

             (and
              (nil? @val)
              (contains? #{10 13} byte))
             (do
               (prn @vacc)
               (vreset! val
                        {k
                         (->> @vacc
                              (map char)
                              (apply str)
                              ((fn [e]
                                 (try
                                   (Integer/parseInt e 16)
                                   (catch NumberFormatException e
                                     0)))))
                         #_(-> (apply str @vacc)
                               (Integer/parseInt 16))})
               (vreset! vacc [])
               #_(vreset! done true)
               acc)

             :else
             (do
               #_(prn (char byte))
               (vswap! vacc conj byte)
               acc))
           (rf acc x)))))))

#_(
   *e
   (in-ns 'jaq.http.xrf.http)
   (require 'jaq.http.xrf.http :reload)
   (int \8) (byte \8)
   (->> #_[56 48 48 48]
        #_[\8 \0 \0 \0]
        "2b77"
        (map char)
        (apply str)
        ((fn [e] (Integer/parseInt e 16))))
   )

(def text-rf
  (fn [rf]
    (let [chunks (volatile! [])
          chunk (volatile! [])
          buf (volatile! nil)
          len (volatile! 1)
          done (volatile! false)
          assoc-fn (fn [acc x]
                     (->> @chunks
                          (assoc x :http/chunks)
                          (rf acc)))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [byte]
               :context/keys [chunked!]
               {:keys [transfer-encoding content-type content-length]} :headers
               :as x}]
         #_(prn ::chunk content-length @len @done @chunks)
         (if (= "chunked" transfer-encoding)
           (cond
             (and
              (not @done)
              (= content-length 0))
             (do
               (vreset! done true)
               (assoc-fn acc x))

             (and
              (not @done)
              (= @len 1)
              (contains? #{13 10} byte))
             acc

             (and
              (not @done)
              (not @buf)
              (= @len 1))
             (do
               (->> content-length (ByteBuffer/allocate) (vreset! buf))
               (.put @buf byte)
               (vswap! len inc)
               acc)

             (and
              @buf
              (not @done)
              (< @len content-length))
             (do
               #_(->> char (vswap! chunk conj))
               (.put @buf byte)
               (vswap! len inc)
               acc)

             #_(and
                @buf
                (not @done)
                (= @len content-length)
                (or (= byte 13) (= byte 10)))
             #_(rf acc)

             (and
              (not @done)
              (= @len content-length))
             (do
               (.put @buf byte)
               (vreset! len 1)
               (vswap! chunks conj (->> @buf
                                        (.flip)
                                        (.decode jaq.http.xrf.params/default-charset)
                                        (.toString)))
               #_(->> @chunks (last) (prn))
               #_(vreset! chunk [])
               (vreset! buf nil)
               (chunked!)
               #_(vreset! done true)
               (assoc-fn acc x))

             :else
             (assoc-fn acc x))
           (cond
             (= content-length 0)
             (do
               (vswap! chunks conj "")
               (vreset! done true)
               (assoc-fn acc x))

             (and
              (not @done)
              (not @buf)
              (= @len 1))
             (do
               (->> content-length (ByteBuffer/allocate) (vreset! buf))
               (.put @buf byte)
               (vswap! len inc)
               acc)

             (and
              @buf
              (not @done)
              (< @len content-length))
             (do
               #_(->> char (vswap! chunk conj))
               #_(prn @len)
               (.put @buf byte)
               (vswap! len inc)
               acc)

             (and
              (not @done)
              (= @len content-length))
             (do
               (.put @buf byte)
               #_(vreset! len 1)
               (vswap! chunks conj (->> @buf
                                        (.flip)
                                        (.decode jaq.http.xrf.params/default-charset)
                                        (.toString)))
               (vreset! buf nil)
               (vreset! done true)
               (assoc-fn acc x))

             :else
             (assoc-fn acc x))))))))

#_(
   (in-ns 'jaq.http.xrf.http)
   )

(def body-rf
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [chunks]
               :keys [char]
               :as x}]
         (->> chunks
              (map (fn [e]
                     (->> e
                          (map (fn [c] (rf acc {:char c}))))))
              (doall))
         (rf acc))))))

#_(
   (in-ns 'jaq.http.xrf.http)
   *e
   )

(def params-rf
  (let [normalize (fn [s] (clojure.string/replace s #"-" "_"))
        encode (fn [reqs [k v]]
                 (conj reqs
                       (->> k (name) (str) (normalize) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                       "="
                       (->> v (str) (sequence (comp rf/index (params/encoder) (map :char))) (apply str))
                       "&"))]
    (comp
     (fn get-rf [rf]
       (fn params
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:http/keys [req method params query-params] :as x}]
          (cond
            (and (= :GET method) params)
            (->> params
                 (reduce encode ["?"])
                 (butlast)
                 (update x :http/req into)
                 (rf acc))

            (and (= :POST method) query-params)
            (->> query-params
                 (reduce encode ["?"])
                 (butlast)
                 (update x :http/req into)
                 (rf acc))

            :else
            (rf acc x)))))
     (fn post-rf [rf]
       (fn params
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:http/keys [method params body]
                {:keys [content-type]} :http/headers
                :as x}]
          (if (and (= :POST method)
                   (= content-type "application/x-www-form-urlencoded")
                   params)
            (->> (assoc x
                        :http/body (->> params
                                        (reduce encode [])
                                        (butlast)
                                        (clojure.string/join)))
                 (rf acc))
            (rf acc x))))))))

#_(
   (in-ns 'jaq.http.xrf.http)
   (into []
         (comp params-rf)
         [#:http{:method :GET :host "host" :path "path"
                 :query-params {:bar :baz}
                 :params {:foo :bar}
                 :req []}])
   *e
   )

(def headers-rf
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
                       (->>
                        (cond
                          (keyword? k)
                          (-> k (name) (str) (string/capitalize))
                          :else
                          k))
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
         (rf acc x))))))

(def http-rf
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
   params-rf
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
   (map (fn [{:http/keys [headers body] :as x}]
          (cond
            (not body)
            (update x :http/headers conj {:content-length 0})

            (string? body)
            (update x :http/headers conj {:content-length (count body)})

            (instance? java.nio.ByteBuffer body)
            (update x :http/headers conj {:content-length (.limit body)}))))
   headers-rf
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "\r\n")))
   (map (fn [{:http/keys [req body] :as x}]
          (if body
            (update x :http/req conj body)
            x)))))

#_(
   (in-ns 'jaq.http.xrf.http)
   (require 'jaq.http.xrf.http :reload)

   (into [] (comp http-rf) [#:http{:method :GET :host "host" :path "path"
                                   :params {:foo :bar}}])
   )
