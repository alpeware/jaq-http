(ns jaq.http.xrf.rf)

#_(def index
  (fn [rf]
    (let [i (volatile! -1)]
      (fn
        ([] (rf))
        ([acc] (->> {:index @i :char :eof} (rf acc) (unreduced) (rf)))
        ([acc {:keys [index char finalized] :as x}]
         (vswap! i inc)
         (rf acc {:index @i :char x}))))))

(def index
  (fn [rf]
    (let [i (volatile! -1)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [index char finalized] :as x}]
         (vswap! i inc)
         (rf acc {:index @i :char x}))))))

;; TODO: credit original
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
