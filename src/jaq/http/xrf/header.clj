(ns jaq.http.xrf.header
  (:require
   [clojure.core.async :as async]
   [clojure.edn :as edn]
   [clojure.string :as string]
   [clojure.java.io :as io]
   [clojure.walk :as walk]
   [net.cgrand.xforms :as x])
  (:import
   [java.util Locale]))

#_(
   (in-ns 'jaq.http.xrf.header)
   )

(def request-line
  (comp
   (fn method [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           k :method
           assoc-fn (fn [acc x] (->>
                                 (:val @rf-state)
                                 (assoc x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn acc x)

            (= char \space)
            (do
              (->> (:acc @rf-state) (apply str) (keyword) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            :else
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (drop 1)
   (fn path [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           assoc-fn (fn [k acc x] (->>
                                   (:val @rf-state)
                                   (assoc x k)
                                   (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn :path acc x)

            (or (= char \?)
                (= char \#)
                (= char \space))
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn :path acc x))

            :else
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (fn query [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           assoc-fn (fn [k acc x] (->>
                                   (:val @rf-state)
                                   (assoc x k)
                                   (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn :query acc x)

            (and
             (empty? (:acc @rf-state))
             (or (= char \space)
                 (= char \#)))
            (do
              (vswap! rf-state assoc :done true)
              (assoc-fn :query acc x))

            (or (= char \space)
                (= char \#))
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn :query acc x))

            (not= char \?)
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (fn fragment [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           k :fragment
           assoc-fn (fn [acc x] (->>
                                 (:val @rf-state)
                                 (assoc x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn acc x)

            (and
             (empty? (:acc @rf-state))
             (= char \space))
            (do
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            (= char \space)
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            (not= char \#)
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (drop 1)
   (fn scheme [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           k :scheme
           assoc-fn (fn [acc x] (->>
                                 (:val @rf-state)
                                 (assoc x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn acc x)

            (= char \/)
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            :else
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (drop 1)
   (fn minor [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           k :minor
           assoc-fn (fn [acc x] (->>
                                 (:val @rf-state)
                                 (assoc x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn acc x)

            (= char \.)
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            :else
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
   (drop 1)
   (fn major [rf]
     (let [rf-state (volatile! {:done false
                                :acc []
                                :val nil})
           k :major
           assoc-fn (fn [acc x] (->>
                                 (:val @rf-state)
                                 (assoc x k)
                                 (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char] :as x}]
          (cond
            (:done @rf-state)
            (assoc-fn acc x)

            (= char \return)
            (do
              (->> (:acc @rf-state) (apply str) (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :done true)
              (assoc-fn acc x))

            :else
            (do
              (vswap! rf-state update :acc conj char)
              (rf acc)))))))
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
   #_(let [finalized (volatile! false)
         buf (volatile! []) ;; TODO: use some 4 char ring buffer
         header-end [\return \newline \return \newline]]
     (map (fn [{:keys [char] :as x}]
            (when-not @finalized
              (prn @buf)
              (vswap! buf (fn [val arg] (->> (conj val arg) (take-last 4) (vec))) char))
            (when (and (not @finalized)
                       (= (take-last 4 @buf) header-end))
              (vreset! finalized true))
            (assoc x :finalized @finalized))))
   (fn [rf]
     (let [finalized (volatile! false)
           header-end [\return \newline \return \newline]
           buf (volatile! []) ;; TODO: use some 4 char ring buffer
           vi (volatile! -4)]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [char] :as x}]
          (when-not @finalized
            #_(prn @buf)
            (vswap! buf (fn [val arg] (->> (conj val arg) (take-last 4) (vec))) char))
          (when (and (not @finalized)
                     (= (take-last 4 @buf) header-end))
            (vreset! finalized true))
          (->> @finalized
               (assoc x :finalized)
               (rf acc))))))
   (fn [rf]
     (let [headers-map (volatile! {})
           rf-state (volatile! {:done false
                                :acc []
                                :val nil
                                :header-name false})
           k :headers
           assoc-fn (fn [acc x]
                      (->>
                       #_(:val @rf-state)
                       @headers-map
                       (assoc x k)
                       (rf acc)))]
       (fn
         ([] (rf))
         ([acc] (rf acc))
         ([acc {:keys [index char finalized] :as x}]
          (cond
            finalized
            (assoc-fn acc x)

            (:done @rf-state)
            (do
              (vswap! headers-map conj (:val @rf-state))
              (vreset! rf-state {:done false
                                 :acc []
                                 :val nil
                                 :header-name false})
              (rf acc))

            (and (= char \:)
                 (not (:header-name @rf-state)))
            (do
              (->> (:acc @rf-state)
                   (apply str)
                   ((fn [e] (.toLowerCase e Locale/ENGLISH)))
                   (keyword)
                   (vswap! rf-state assoc :val))
              (vswap! rf-state assoc :header-name true)
              (vswap! rf-state assoc :acc [])
              (rf acc))

            (and (= char \space)
                 (empty? (:acc @rf-state)))
            (do
              (rf acc))

            (and (= char \return)
                 (:val @rf-state))
            (let [hk (:val @rf-state)
                  hv (->> (:acc @rf-state) (apply str))]
              (vswap! rf-state assoc :val {hk hv})
              (vswap! rf-state assoc :done true)
              (rf acc))

            (and (not= char \return)
                 (not= char \newline))
            (do
              (vswap! rf-state update :acc conj char)
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
