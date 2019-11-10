(ns jaq.http.xrf.params)

(def decode
  (fn [rf]
    (let [decode (volatile! false)
          vacc (volatile! [])
          length (volatile! 0)
          rf-state (volatile! {:decode false
                               :acc []})
          ]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [index char]
               {:keys [content-length]} :headers
               :as x}]
         (vswap! length inc)
         (cond
           (= char \+)
           (->> (assoc! x :char \space)
                (rf acc))

           (= char \&)
           (->> (assoc! x :char :sep)
                (rf acc))

           (= char \%)
           (do
             (vreset! decode true)
             (rf acc))

           @decode
           (do
             (vswap! vacc conj char)
             (if (-> @vacc (count) (= 2))
               (->> @vacc
                    (apply str)
                    ((fn [e]
                       (vreset! decode false)
                       (vreset! vacc [])
                       (-> e
                           (Integer/parseInt 16)
                           (clojure.core/char))))
                    (assoc! x :char)
                    (rf acc))
               (rf acc)))

           :else
           (rf acc x))
         (when (= @length (Integer/parseInt content-length))
           (->> (assoc! x :char :eof)
                (rf acc))))))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.params)
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
     decode)
    s)

   )

(def params
  (comp
   decode
   (fn [rf]
     (let [params-map (volatile! {})
           done (volatile! false)
           param-name (volatile! false)
           vacc (volatile! [])
           val (volatile! nil)
           k :params
           assoc-fn (fn [acc x] (->>
                                 @params-map
                                 (assoc! x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char]

                :as x}]
          (cond
            (and (= char \=)
                 (not @param-name))
            (do
              (->> @vacc
                   (apply str)
                   (keyword)
                   (vreset! val))
              (vreset! vacc [])
              (vreset! param-name true)
              (rf acc))

            (and (or (= char :sep) (= char :eof))
                 @val)
            (let [pk @val
                  pv (->> @vacc (apply str))]
              (vswap! params-map conj {pk pv})
              (vreset! done false)
              (vreset! param-name false)
              (vreset! vacc [])
              (vreset! val nil)
              (if (= char :eof)
                (assoc-fn acc x)
                (rf acc)))

            :else
            (do
              (vswap! vacc conj char)
              (rf acc)))))))))

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
