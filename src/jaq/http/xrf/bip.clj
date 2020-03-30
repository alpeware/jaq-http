(ns jaq.http.xrf.bip
  (:require
   [clojure.string :as string]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.nio ByteBuffer ByteOrder CharBuffer]))

(def default-page-size 4096)
(def default-size (* default-page-size 2))

;; Bip Buffer
;; see https://www.codeproject.com/Articles/3479/The-Bip-Buffer-The-Circular-Buffer-with-a-Twist
;; and http://read.pudn.com/downloads176/doc/comm/818647/BipBuffer.h__.htm

(defn freespace-a [buf-a]
  (- (.capacity buf-a) (.position buf-a)
     (.limit buf-a)))

(defn ^ByteBuffer reserve [buf buf-a buf-b]
  (cond
    (> (.limit buf-b) 0)
    (-> buf
        (.position (.limit buf-b))
        (.limit (.position buf-a))
        (.slice))

    (>= (freespace-a buf-a) (.position buf-a))
    (-> buf
        (.position (+ (.limit buf-a)
                      (.position buf-a)))
        (.limit (+ (.capacity buf)))
        (.slice))

    :else
    (-> buf
        (.position 0)
        (.slice)
        (.limit (.position buf-a)))))

(defn ^ByteBuffer commit [buf-a buf-b bb]
  (cond
    (= (.limit buf-a) (.limit buf-b) 0)
    (-> buf-a (.limit (.limit bb)))

    (>= (freespace-a buf-a) (.position buf-a))
    (let [lim (-> buf-a (.limit) (+ (.limit bb)))]
      (-> buf-a (.limit lim)))

    :else
    (let [lim (-> buf-b (.limit) (+ (.limit bb)))]
      (-> buf-b (.limit lim)))))

(defn ^ByteBuffer block [buf-a]
  (.slice buf-a))

(defn ^ByteBuffer decommit [buf-a buf-b bb]
  (let [pos (-> buf-a (.position) (+ (.position bb)))
        lim (-> buf-a (.limit))]
    (if (>= pos lim)
      (do
        (-> buf-a (.position (.position buf-b)) (.limit (.limit buf-b)))
        (-> buf-b (.position 0) (.limit 0)))
      (-> buf-a (.position pos)))
    bb))

(def bip-rf
  (fn [rf]
    (let [bip (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:context/keys [page-size bip-size]
               :or {page-size default-page-size
                    bip-size default-size}
               :as x}]
         (when-not @bip
           (let [buf (-> bip-size
                         (+ page-size)
                         (ByteBuffer/allocateDirect)
                         (.alignedSlice page-size)
                         (.order (ByteOrder/nativeOrder)))
                 buf-a (-> buf (.duplicate) (.limit 0))
                 buf-b (-> buf (.duplicate) (.limit 0))]
             (->> {:buf buf
                   :buf-a buf-a :buf-b buf-b
                   :reserve (partial reserve buf buf-a buf-b)
                   :commit (partial commit buf-a buf-b)
                   :block (partial block buf-a)
                   :decommit (partial decommit buf-a buf-b)}
                  (vreset! bip))))
         (->> (assoc x :context/bip @bip)
              (rf acc)))))))

#_(
   (into []
         (comp
          bip-rf
          (map (fn [{{:keys [reserve commit block decommit]} :context/bip
                     :as x}]
                 (let [bb (reserve)]
                   (.putChar bb \F)
                   (.flip bb)
                   (commit bb)
                   x)))
          (map (fn [{{:keys [reserve commit block decommit]} :context/bip
                     :as x}]
                 (let [bb (block)
                       c (.getChar bb)]
                   (decommit bb)
                   (assoc x :c c))))
          (map :c))
         [{}])

   (into []
         (comp
          bip-rf
          (map (fn [{{:keys [buf reserve commit block decommit]} :context/bip
                     :as x}]
                 (let [bb (reserve)]
                   (assoc x :c buf))))
          #_(map (fn [{{:keys [buf reserve commit block decommit]} :context/bip
                     :as x}]
                 (let [bb (reserve)]
                   (.putChar bb \F)
                   (.flip bb)
                   (commit bb)
                   x)))
          #_(map (fn [{{:keys [reserve commit block decommit]} :context/bip
                     :as x}]
                 (let [bb (block)
                       c (.getChar bb)]
                   (decommit bb)
                   (assoc x :c c))))
          #_(map :c))
         [{:context/bip-size page-size}])

   (-> page-size
       (+ page-size)
       (ByteBuffer/allocateDirect)
       (.alignedSlice page-size)
       (.order (ByteOrder/nativeOrder)))
   )

#_(
   *ns*
   *e
   (require 'jaq.http.xrf.bip :reload)
   (let [write-buf (-> size
                       (+ page-size)
                       (ByteBuffer/allocateDirect)
                       (.alignedSlice page-size)
                       (.order (ByteOrder/nativeOrder)))
         write-buf-a (.duplicate buf)
         write-buf-b (.duplicate buf)
         freespace-a-fn (fn []
                          (- (.capacity write-buf-a) (.position write-buf-a)
                             (.limit write-buf-a)))
         freespace-b-fn (fn []
                          (- (.position write-buf-a) (.position write-buf-b)
                             (.limit write-buf-b)))
         reserve-fn (fn []
                      (if (> (.limit write-buf-b) 0)
                        (let [freespace (freespace-b-fn)]
                          (-> write-buf
                              (.position (.limit write-buf-b))
                              (.limit (.position write-buf-a))
                              (.slice)))
                        (let [freespace (freespace-a-fn)]
                          (if (>= freespace (.position write-buf-a))
                            (-> write-buf
                                (.position (+ (.limit write-buf-a)
                                              (.position write-buf-a)))
                                (.limit (+ (.capacity write-buf)))
                                (.slice))
                            (-> write-buf
                                (.position 0)
                                (.slice)
                                (.limit (.position write-buf-a)))))))
         commit-fn (fn [bb]
                     (cond
                       (= (.limit write-buf-a) (.limit write-buf-b) 0)
                       (-> write-buf-a (.limit (.limit bb)))

                       (>= (freespace-a-fn) (.position write-buf-a))
                       (let [lim (-> write-buf-a (.limit) (+ (.limit bb)))]
                         (-> write-buf-a (.limit lim)))

                       :else
                       (let [lim (-> write-buf-b (.limit) (+ (.limit bb)))]
                         (-> write-buf-b (.limit lim)))))
         block-fn (fn []
                    (.slice write-buf-a))
         decommit-fn (fn [bb]
                       (let [pos (-> write-buf-a (.position) (+ (.position bb)))
                             lim (-> write-buf-a (.limit))]
                         (if (>= pos lim)
                           (do
                             (-> write-buf-a (.position (.position write-buf-b)))
                             (-> write-buf-a (.limit (.limit write-buf-b)))
                             (-> write-buf-b (.position 0))
                             (-> write-buf-b (.limit 0)))
                           (-> write-buf-a (.position pos)))
                         bb))]
     (.limit write-buf-a 0)
     (.limit write-buf-b 0)
     {:write-buf write-buf
      :write-buf-a write-buf-a :write-buf-b write-buf-b
      :reserve reserve-fn :commit commit-fn
      :block block-fn :decommit decommit-fn}))
