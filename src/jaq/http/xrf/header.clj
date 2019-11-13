(ns jaq.http.xrf.header
  (:require
   [jaq.http.xrf.rf :as rf]
   [taoensso.tufte :as tufte])
  (:import
   [java.util Locale]))

#_(
   (in-ns 'jaq.http.xrf.header)
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


   )

(def request-line
  (comp
   (fn method [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :method
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (= char \space)
            (tufte/p
             ::method
             (do
               (->> @vacc (apply str) (keyword) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            :else
            (tufte/p
             ::method
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (drop 1)
   (fn path [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :path
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (or (= char \?)
                (= char \#)
                (= char \space))
            (tufte/p
             ::path
             (do
               (->> @vacc (apply str) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            :else
            (tufte/p
             ::path
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (fn query [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :query
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (and
             (empty? @vacc)
             (or (= char \space)
                 (= char \#)))
            (tufte/p
             ::query
             (do
               (vreset! done true)
               (assoc-fn acc x)))

            (or (= char \space)
                (= char \#))
            (tufte/p
             ::query
             (do
               (->> @vacc (apply str) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            (not= char \?)
            (tufte/p
             ::query
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (fn fragment [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :fragment
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (and
             (empty? @vacc)
             (= char \space))
            (do
              (vreset! done true)
              (assoc-fn acc x))

            (= char \space)
            (tufte/p
             ::fragment
             (do
               (->> @vacc (apply str) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            (not= char \#)
            (tufte/p
             ::fragment
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (drop 1)
   (fn scheme [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :scheme
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (= char \/)
            (tufte/p
             ::scheme
             (do
               (->> @vacc (apply str) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            :else
            (tufte/p
             ::scheme
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (drop 1)
   (fn minor [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :minor
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (= char \.)
            (tufte/p
             ::minor
             (do
               (->> @vacc (apply str) (Integer/parseInt) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            :else
            (tufte/p
             ::minor
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (drop 1)
   (fn major [rf]
     (let [done (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :major
           assoc-fn (fn [acc x] (->>
                                 @val
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            @done
            (assoc-fn acc x)

            (= char \return)
            (tufte/p
             ::major
             (do
               (->> @vacc (apply str) (Integer/parseInt) (vreset! val))
               (vreset! done true)
               (assoc-fn acc x)))

            :else
            (tufte/p
             ::major
             (do
               (vswap! vacc conj char)
               (rf acc))))))))
   (drop 2)))

#_(

   (in-ns 'jaq.http.xrf.header)
   (let [a (volatile! [:foo :bar \return \newline \return])
         end [\return \newline \return \newline]]
     (vswap! a (fn [val arg] (->> (conj val arg) (take-last 4) (vec))) \newline)
     #_(->> (conj a \newline) (take-last 4) #_(= end)))

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
            (tufte/p
             ::finalized
             (vswap! buf (fn [val arg] (->> (conj val arg) (take-last 4) (vec))) char)))
          (when (and (not @finalized)
                     (= (take-last 4 @buf) header-end))
            (vreset! finalized true))
          (->> @finalized
               (assoc! x :finalized)
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
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
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
   (in-ns 'jaq.http.xrf.header)
   *e

   (sequence
    (comp
     jaq.http.server.nio/index
     request-line
     headers
     (drop 1)
     #_(take 5)
     #_(map :char))
    jaq.http.server.nio/s)

   *e
   )
