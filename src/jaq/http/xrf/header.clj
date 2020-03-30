(ns jaq.http.xrf.header
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.params :as params])
  (:import
   [java.util Locale]))

#_(
   *ns*
   (require 'jaq.http.xrf.header :reload)
   (in-ns 'jaq.http.xrf.header)
   (fnp foo [])
   )

(defn split [k pred f]
  (fn [rf]
    (let [done (volatile! false)
          vacc (volatile! [])
          val (volatile! nil)
          assoc-fn (fn [acc x] (->>
                                @val
                                (assoc x k)
                                (rf acc)))]
      (fn split
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:keys [index char] :as x}]
            (cond
              @done
              (assoc-fn acc x)

              (pred char)
              (do
                (->> @vacc (apply str) f (vreset! val))
                (vreset! done true)
                (assoc-fn acc x))

              :else
              (do
                (vswap! vacc conj char)
                (rf acc))))))))

#_(



   )

(def query
  (fn [rf]
    (let [parser-rf ((comp
                      (params/decoder)
                      params/params) rf)
          decode (volatile! false)
          length (volatile! 0)
          done (volatile! true)]
      (fn query
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:keys [index char] :as x}]
            (vswap! length inc)
            (cond
              (and (= @length 1)
                   (= char \?))
              (do
                (vreset! decode true)
                (vreset! done false)
                acc)

              (and @done (not @decode))
              (rf acc x)

              #_(and @decode (= char \space))
              #_(->> (assoc x :eob true)
                     (parser-rf acc))

              @decode
              (do
                (parser-rf acc x))))))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.header)
   (let [buf "?foo=bar+baz "
         xform (comp
                rf/index
                query)]
     (->> (sequence xform buf) (first) :params))

   (let [buf jaq.http.client.nio/b
         xform (comp
                rf/index
                scheme
                (drop 1)
                minor
                (drop 1)
                major
                (drop 1)
                (split :status
                       (comp not (partial contains? numbers))
                       (fn [s] (Integer/parseInt s)))
                (drop 1)
                (split :reason (comp not (partial contains? alphanumeric))
                       identity)
                (drop 2)
                headers)]
     (->> (sequence xform buf) (first) :reason))
   )

(def method
  (split :method (partial contains? #{\space}) keyword))

(def path
  (split :path (partial contains? #{\? \# \space}) identity))

(def scheme
  (split :scheme (partial contains? #{\/}) identity))

(def numbers
  (->> (range 10)
       (map (fn [i]
              (-> \0 (int) (+ i) (char))))
       (set)))

(def alphanumeric
  (->> (range 26)
       (map (fn [i]
              [(-> \A (int) (+ i) (char))
               (-> \a (int) (+ i) (char))]))
       (mapcat identity)
       (set)))

(def minor
  (split :minor
         (comp not (partial contains? numbers))
         (fn [s] (Integer/parseInt s))))

(def major
  (split :major
         (comp not (partial contains? numbers))
         (fn [s] (Integer/parseInt s))))

(def fragment
  (split :fragment
         (partial contains? #{\space})
         (fn [s] (if (string/blank? s) nil s))))

(def status
  (split :status
         (comp not (partial contains? numbers))
         (fn [s] (Integer/parseInt s))))

(def reason
  (split :reason
         (comp not (partial contains? (set/union #{\space} alphanumeric)))
         identity))

#_(
   *e
   )

(def whitespace #{\space \tab})

(defn ignore [s]
  (comp
   (drop-while (fn [{:keys [char]}]
                 (contains? s char)))))

(def ignore-whitespace
  (comp
   (ignore whitespace)))

(def response-line
  (comp
   scheme
   (ignore #{\/})
   minor
   (ignore #{\.})
   major
   ignore-whitespace
   status
   ignore-whitespace
   reason
   (ignore #{\return \newline})))

#_(
   (in-ns 'jaq.http.xrf.header)

   (into [] (comp
             rf/index
             response-line)
         "HTTP/1.1 200 OK\n\r ")
   )

(def request-line
  (comp
   method
   (drop 1)
   path
   query
   fragment
   (drop 1)
   scheme
   (drop 1)
   minor
   (drop 1)
   major
   (drop 2)))

#_(
   (in-ns 'jaq.http.xrf.header)
   )

(def headers
  (comp
   (fn [rf]
     (let [finalized (volatile! false)
           header-end [\return \newline \return \newline]
           buf (volatile! []) ;; TODO: use ArrayDeque
           vi (volatile! -4)]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [char] :as x}]
          (when-not @finalized
            (vswap! buf (fn [val arg] (->> (conj val arg) (take-last 4) (vec))) char))
          (when (and (not @finalized)
                     (= (take-last 4 @buf) header-end))
            (vreset! finalized true))
          (->> @finalized
               (assoc x :finalized)
               (rf acc))))))
   (fn [rf]
     (let [headers-map (volatile! {})
           done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           header-name (volatile! false)
           k :headers
           assoc-fn (fn [acc x] (->>
                                 @headers-map
                                 (assoc x k)
                                 (rf acc)))]
       (fn header
            ([] (rf))
            ([acc] (rf acc))
            ([acc {:keys [index char finalized] :as x}]
             (cond
               finalized
               (assoc-fn acc x)

               @done
               (do
                 (vswap! headers-map conj @val)
                 (vreset! done false)
                 (vreset! vacc [])
                 (vreset! val nil)
                 (vreset! header-name false)
                 (rf acc))

               (and (= char \:)
                    (not @header-name ))
               (do
                 (->> @vacc
                      (map (fn [^Character e] (Character/toLowerCase e)))
                      (apply str)
                      #_((fn [e] (.toLowerCase e Locale/ENGLISH)))
                      (keyword)
                      (vreset! val))
                 (vreset! header-name true)
                 (vreset! vacc [])
                 (rf acc))

               (and (= char \space)
                    (empty? @vacc))
               (do
                 (rf acc))

               (and (= char \return)
                    @val)
               (let [hk @val
                     hv (if (= hk :content-length)
                          (->> @vacc (apply str) (Integer/parseInt))
                          (->> @vacc (apply str)))]
                 (vreset! val {hk hv})
                 (vreset! done true)
                 (rf acc))

               (and (not= char \return)
                    (not= char \newline))
               (do
                 (vswap! vacc conj char)
                 (rf acc)))))))))

#_(
   (require 'jaq.http.xrf.header)
   (in-ns 'jaq.http.xrf.header)
   *e

   (tufte/profile
    {}
    (let [buf "GET / HTTP/1.1\r\n "
          rf (let [result (volatile! nil)]
               (fn
                 ([] @result)
                 ([acc] acc)
                 ([acc x] (vreset! result (persistent! x)) acc)))
          xform (comp
                 rf/index
                 request-line)
          xf (xform rf)]
      (run! (fn [x] (tufte/p :xf (xf nil x))) buf)
      (rf)))

   (tufte/profile
    {}
    (let [buf "GET / HTTP/1.1\r\nHost: foobar\r\n\r\n"
          rf (let [result (volatile! nil)]
               (fn
                 ([] @result)
                 ([acc] acc)
                 ([acc x] (vreset! result (persistent! x)) acc)))
          xform (comp
                 rf/index
                 request-line
                 headers)]
      (doseq [i (range 100)]
        (let [xf (xform rf)]
          (run! (fn [x] (xf nil x)) buf)))
      (rf)))

   *e
   )
