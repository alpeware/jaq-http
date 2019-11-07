(ns jaq.http.xrf.params)

(def decode
  (fn [rf]
    (let [rf-state (volatile! {:decode false
                               :acc []})
          length (volatile! 0)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [index char]
               {:keys [content-length]} :headers
               :as x}]
         (vswap! length inc)
         (cond
           (= char \+)
           (->> (assoc x :char \space)
                (rf acc))

           (= char \&)
           (->> (assoc x :char :sep)
                (rf acc))

           (= char \%)
           (do
             (vswap! rf-state assoc :decode true)
             (rf acc))

           (:decode @rf-state)
           (do
             (vswap! rf-state update :acc conj char)
             (if (-> @rf-state :acc (count) (= 2))
               (->> @rf-state
                    :acc
                    (apply str)
                    ((fn [e]
                       (vswap! rf-state conj {:decode false :acc []})
                       (-> e
                           (Integer/parseInt 16)
                           (clojure.core/char))))
                    (assoc x :char)
                    (rf acc))
               (rf acc)))

           :else
           (rf acc x))
         (when (= @length (Integer/parseInt content-length))
           (->> (assoc x :char :eof)
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
           rf-state (volatile! {:done false
                                :acc []
                                :val nil
                                :param-name false})
           k :params
           assoc-fn (fn [acc x]
                      (->>
                       @params-map
                       (assoc x k)
                       (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char]

                :as x}]
          (cond
            (and (= char \=)
                 (not (:param-name @rf-state)))
            (do
              (->> (:acc @rf-state)
                   (apply str)
                   (keyword)
                   (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :acc [])
              (vswap! rf-state assoc :param-name true)
              (rf acc))

            (and (or (= char :sep) (= char :eof))
                 (:val @rf-state))
            (let [pk (:val @rf-state)
                  pv (->> (:acc @rf-state) (apply str))]
              (vswap! params-map conj {pk pv})
              (vreset! rf-state {:done false
                                 :acc []
                                 :val nil
                                 :param-name false})
              (if (= char :eof)
                (assoc-fn acc x)
                (rf acc)))

            :else
            (do
              (vswap! rf-state update :acc conj char)
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
