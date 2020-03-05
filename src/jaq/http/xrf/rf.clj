(ns jaq.http.xrf.rf
  (:require
   [taoensso.tufte :as tufte]))

(def index
  (fn [rf]
    (let [i (volatile! -1)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (vswap! i inc)
         (rf acc {:index @i :char x}))))))

(defn result-fn []
  (let [result (volatile! nil)]
    (fn
      ([] @result)
      ([acc] acc)
      ([acc x] (vreset! result x) acc))))

;; https://github.com/pangloss/transducers/blob/master/src/xn/transducers.cljc
(defn branch
  "Will route data down one or another transducer path based on a predicate
   and merge the results."
  [pred true-xform false-xform]
  (fn [rf]
    (let [true-rf (true-xform rf)
          false-rf (false-xform rf)]
      (fn
        ([] (true-rf) (false-rf))
        ([result]
         (true-rf (false-rf result)))
        ([result input]
         (if (pred input)
           (true-rf result input)
           (false-rf result input)))))))

(def identity-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc x]
       (rf acc x)))))

;; TODO: choose


;; example to recur locally
(def recur-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:keys [foo y] :as x}]
       (if (> y 5)
         (rf acc x)
         (recur acc (update x :y inc)))))))

#_(
   (sequence (comp
              recur-rf
              (take 2)
              #_(map (fn [x] (prn x) x)))
             (->> (range 10) (map (fn [e] {:foo e :y 0}))))
   )

;; example to enqueue another value
(def loop-rf
  (fn [rf]
    (fn
      ([] (rf))
      ([acc] (rf acc))
      ([acc {:keys [] :as x}]
       (->> (assoc x :context/loop-rf rf)
            (rf acc))))))


#_(

   (into [] (comp
              loop-rf
              (fn sum [rf]
                (let [s (volatile! 0)]
                  (fn
                    ([] (rf))
                    ([acc] (rf acc))
                    ([acc {:keys [i loop-rf] :as x}]
                     (vswap! s + i)
                     (rf acc (assoc x :sum @s))))))
              (map (fn [{:keys [i] :as x}] (update x :i inc)))
              (fn ss [rf]
                (fn
                  ([] (rf))
                  ([acc] (rf acc))
                  ([acc {:keys [i loop-rf] :as x}]
                   (if (and (>= i 10) (< i 20))
                     (loop-rf acc x)
                     (rf acc x)))))
              (map (fn [x] (select-keys x [:i :sum]))))
             (->> (range 10)
                  (map (fn [i] {:i i})))
             )

   )



#_(
*ns*
(in-ns 'jaq.http.xrf.rf)
)
