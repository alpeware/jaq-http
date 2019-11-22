(ns jaq.http.xrf.params
  "Transducers to handle URL encoded data."
  (:require
   [clojure.string :as string]
   [taoensso.tufte :as tufte :refer [defnp fnp p]])
  (:import
   [java.nio.charset Charset]
   [java.nio ByteBuffer]))

(def ^Charset default-charset
  "Default Charset for decoding."
  (Charset/forName "UTF-8"))

(defnp ^String mapper
  "Maps a vec of hex ints to a string using the specified encoding."
  [v ^Charset charset]
  (->> v
       (map (fn [e] (Integer/parseInt e 16)))
       (map unchecked-byte)
       (byte-array)
       (ByteBuffer/wrap)
       (.decode charset)
       (.toString)))

(defnp decoder
  "Transducer to perform URL decoding using the optional charset
  or defaulting to UTF-8."
  [& [^Charset charset]]
  (let [charset (or charset default-charset)]
    (fn [rf]
      (let [decode (volatile! false)
            done (volatile! false)
            vacc (volatile! [])
            v (volatile! [])
            length (volatile! 0)
            purge-fn (fn [acc x]
                       (if (seq @v)
                         (let [acc' (loop [s (mapper @v charset)
                                           acc' acc]
                                      (if (empty? s)
                                        acc'
                                        (recur (rest s)
                                               (->> (first s)
                                                    (assoc x :char)
                                                    (rf acc')))))]
                           (vreset! v [])
                           [acc' x])
                         [acc x]))
            assoc-fn (fn [acc x content-length c]
                       (let [[acc' x'] (purge-fn acc x)]
                         (if
                           (and content-length
                                (= @length content-length))
                           (->> (conj x' {:char c :eob true})
                                (rf acc'))
                           (do
                             (->> (assoc x' :char c)
                                  (rf acc'))))))]
        (fn
          ([] (rf))
          ([acc] (rf acc))
          ([acc {:keys [index char]
                 {:keys [content-length]} :headers
                 :as x}]
           (vswap! length inc)
           (cond
             @done
             (rf acc x)

             (= char \+)
             (assoc-fn acc x content-length \space)

             (= char \&)
             (assoc-fn acc x content-length :sep)

             (= char \=)
             (assoc-fn acc x content-length :assign)

             (= char \%)
             (do
               (vreset! decode true)
               acc)

             (= char \space)
             (do
               (vreset! done true)
               (assoc-fn acc x @length char))

             @decode
             (do
               (vswap! vacc conj char)
               (when (-> @vacc (count) (= 2))
                 (->> @vacc (apply str) (vswap! v conj))
                 (vreset! decode false)
                 (vreset! vacc []))
               (if (and content-length
                        (= @length content-length))
                 (let [[acc x] (purge-fn acc x)]
                   acc)
                 acc))

             :else
             (assoc-fn acc x content-length char))))))))

#_(
   *e
   *ns*
   (in-ns 'jaq.http.xrf.params)

   (let [original "a$\302d &"
         encoded (java.net.URLEncoder/encode original "UTF-8")
         xform (comp
                jaq.http.xrf.rf/index
                (map (fn [x]
                       (assoc x :headers {:content-length (count encoded)})))
                (decoder))
         decoded (->> (sequence xform encoded)
                      (map :char)
                      #_(apply str))]
     [original encoded decoded])
   )

(def params
  "Transducer to process key/val pairs into a map.

  Should be used w/ decoder xf for pre-processing."
  (comp
   (fn [rf]
     (let [params-map (volatile! {})
           done (volatile! false)
           param-name (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :params
           assoc-fn (fn [acc x] (->>
                                 @params-map
                                 (assoc x k)
                                 (rf acc)))]
       (fnp
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char eob]
                :as x}]
          (cond

            ;; only key but no value
            (and (= char :assign) eob)
            (let [pk (->> @vacc
                          (apply str)
                          (keyword)
                          (vreset! val))
                  pv nil]
              (vswap! params-map conj {pk pv})
              (vreset! done false)
              (vreset! param-name false)
              (vreset! vacc [])
              (vreset! val nil)
              (assoc-fn acc x))

            (= char :assign)
            (do
              (->> @vacc
                   (apply str)
                   (keyword)
                   (vreset! val))
              (vreset! vacc [])
              (vreset! param-name true)
              acc)

            (and (= char :sep) @val)
            (let [pk @val
                  pv (if (seq @vacc)
                       (->> @vacc (apply str))
                       nil)]
              (vswap! params-map conj {pk pv})
              (vreset! done false)
              (vreset! param-name false)
              (vreset! vacc [])
              (vreset! val nil)
              acc)

            (and eob @val)
            (let [pk @val
                  pv (->> (if (= char \space)
                            @vacc
                            (conj @vacc char))
                          (apply str)
                          ((fn [s] (if (string/blank? s)
                                     nil
                                     s))))]
              (vswap! params-map conj {pk pv})
              (vreset! done false)
              (vreset! param-name false)
              (vreset! vacc [])
              (vreset! val nil)
              (assoc-fn acc x))

            :else
            (do
              (vswap! vacc conj char)
              acc))))))))

#_(
   *e
   *ns*
   (in-ns 'jaq.http.xrf.params)

   (let [original {:foo nil}
         encoded (str
                  (->> original (map (fn [[k v]] (str (name k) "=" v))) (clojure.string/join "&"))
                  " ")
         xform (comp
                jaq.http.xrf.rf/index
                (map (fn [{:keys [char] :as x}]
                       (assoc x :char
                              (condp = char
                                \= :assign
                                \& :sep
                                char))))
                (map (fn [{:keys [index] :as x}]
                       (if (= index (-> encoded (count) (dec)))
                         (assoc x :eob true)
                         x)))
                params)
         m (->> (sequence xform encoded)
                (first)
                :params)]
     [original encoded m (= original m)])

   )

(def body
  (comp
   (decoder)
   params))

#_(
   (in-ns 'jaq.http.xrf.params)

   (def s "form=%2Ans%2A&foo=bar")
   s
   *ns*
   *e
   (sequence
    (comp
     (fn [rf]
       (let [i (volatile! -1)]
         (fn
           ([] (rf))
           ([acc] (->> {:index @i :char :eof} (rf acc) (unreduced) (rf)))
           ([acc {:keys [index char finalized] :as x}]
            (vswap! i inc)
            (rf acc {:index @i :char x})))))
     params)
    s
    #_(->>
       (clojure.string/split jaq.http.server.nio/s #"\r\n\r\n")
       (second)))

   )
