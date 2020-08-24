(ns jaq.http.xrf.rf
  (:require
   [net.cgrand.xforms :as x]))

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

(defn once-rf [f]
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (if @once
           (rf acc x)
           (do
             (vreset! once true)
             (->> (f x)
                  (rf acc)))))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   )

(defn repeatedly-rf [xf]
  (fn [rf]
    (let [val (volatile! nil)
          vacc (volatile! nil)
          init (fn [] (xf (result-fn)))
          xf-rf (volatile! (init))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (@xf-rf acc x)
         (if-let [x' (@xf-rf)]
           (do
             (vreset! xf-rf (init))
             (rf acc x'))
           acc))))))

(defn repeat-rf [n xf]
  (fn [rf]
    (let [i (volatile! n)
          val (volatile! nil)
          vacc (volatile! nil)
          init (fn [] (xf (result-fn)))
          xf-rf (volatile! (init))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (if (> @i 0)
           (do
             (@xf-rf acc x)
             (if-let [x' (@xf-rf)]
               (do
                 (vreset! xf-rf (init))
                 (vswap! i dec)
                 (if (= @i 0)
                   (rf acc x')
                   acc))
               acc))
           (rf acc x)))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   (into [] (repeat-rf 5 (comp
                          (map inc))) (range 10))
   )

(defn one-rf [k xf]
  (fn [rf]
    (let [once (volatile! false)
          val (volatile! nil)
          xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (if @once
           (rf acc (assoc x k @val))
           (do
             (xrf acc x)
             (if-let [x' (xrf)]
               (do
                 (prn ::done)
                 (vreset! val x')
                 (vreset! once true)
                 (rf acc (assoc x k x')))
               acc))))))))

(defn catch-rf [e f xf]
  (fn [rf]
    (let [xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (let [x' (try
                    (xrf nil x)
                    (catch Exception ex
                      ex))]
           (cond
             (instance? e x')
             (rf acc (f (assoc x :error/exception x')))

             (instance? Exception x')
             (throw x')

             (xrf)
             (rf acc (xrf))

             :else
             acc)))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   *e

   (into []
         (catch-rf
          ArithmeticException
          (fn [x] (assoc x :c :nan))
          (comp
           (map (fn [{:keys [a b] :as x}]
                  (assoc x :c (/ a b))))))
         [{:a 4 :b 0} {:a 3 :b 1}])


   (let [e ArithmeticException]
     (try (/ 9 0)
          (catch Exception ex
            (throw ex)
            #_(instance? e ex))))
   )

(defn choose-rf [pred xfs]
  (fn [rf]
    (let [rfs (->> xfs
                   (map (fn [[k xf]]
                          [k (xf rf)]))
                   (into {}))
          default-rf (or (:default rfs) rf)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (-> (get rfs (pred x) default-rf)
             (apply [acc x])))))))

#_(

   (into []
         (choose-rf :xf {:foo (map (fn [x]
                                     (assoc x :v :foo-bar)))})
         [{:xf :foo :v :foo} {:xf :bar :v :bar} {:xf :default :v :default}])
   *e
   *ns*

   )

(defn debug-rf [tag]
  (fn [rf]
    (let [once (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (when-not @once
           (prn tag x)
           (vreset! once true))
         (rf acc x))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   *e
   (into [] (comp
             (once-rf
              (take-while #{0 1 5 6}))
             )
         (range 20))

   (into [] (comp
             (take-while #{0 1 5 6}))
         (range 10))

   (into [] (comp
             (once-rf
              (comp
               index
               jaq.http.xrf.header/response-line
               (take 1)
               #_(x/into []))))
         ["HTTP/1.1 200 " "OK\n\r " "HTTP/1.1 400 FORBIDDEN\n\r " "HTTP/1.1 400"])

   (into [] (comp
             index
             (once-rf
              (comp
               jaq.http.xrf.header/response-line
               (take 1))))
         "HTTP/1.1 200 OK\n\r ")

   *e
   )

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

;; cljs event handling
;; TODO: adapt for clj

(defn selector! []
  (volatile! {}))

(defn register! [selector event-target event-type attachment channel]
  (vswap! selector assoc-in [event-target event-type channel] attachment))

(defn deregister! [selector event-target event-type channel]
  (vswap! selector update-in [event-target event-type] dissoc channel))

(def selector-rf
  (fn [rf]
    (let [sl (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :window/keys [selector]
               :as x}]
         (when-not @sl
           (let [selector (or selector (selector!))]
             (->> selector
                  (vreset! sl))))
         (->> (assoc x :window/selector @sl)
              (rf acc)))))))

#?(:cljs
   (def select-rf
     (fn [rf]
       (let [once (volatile! nil)]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:window/keys [selector]
                  :event/keys [types]
                  event-target :event/target
                  :as x}]
            (when-not @once
              (prn ::listeners event-target types)
              (doseq [e types]
                (-> event-target
                    (.addEventListener
                     (name e)
                     (fn [event]
                       (let [event-name (-> event (.-constructor) (.-name) (keyword))
                             event-type (-> event (.-type) (keyword))
                             target (-> event (.-target))]
                         #_(.info js/console "event" event)
                         #_(prn ::selector selector)
                         (doseq [{:context/keys [rf acc x]
                                  :window/keys [channel]} (-> @selector
                                                              (get-in [event-target event-type])
                                                              (vals))]
                           (prn ::event channel)
                           (rf acc (assoc x
                                          :context/rf rf
                                          :context/x x
                                          :event/event event
                                          :event/name event-name
                                          :event/type event-type
                                          :event/target target
                                          :window/selector selector
                                          :window/channel channel))
                           (when (rf)
                             (deregister! selector event-target event-type channel))))))))
              (vreset! once true))
            (rf acc x)))))))

(defn bind-rf
  ([] (fn [rf]
        (let [channel (volatile! nil)]
          (fn
            ([] (rf))
            ([acc] (rf acc))
            ([acc {:window/keys [selector]
                   :event/keys [target type types]
                   :as x}]
             (when-not @channel
               (->> (random-uuid)
                    (vreset! channel))
               ;; TODO: remove support for type
               (doseq [t (if type [type] types)]
                 (register! selector
                            target
                            t
                            (-> x
                                (dissoc :window/selector)
                                (assoc :context/x (dissoc x :window/selector)
                                       :window/channel @channel
                                       :context/rf rf))
                            @channel)))
             acc)))))
  ([xf] (fn [rf]
          (let [channel (volatile! nil)]
            (fn
              ([] (rf))
              ([acc] (rf acc))
              ([acc {:window/keys [selector]
                     :event/keys [target type types]
                     :as x}]
               (when-not @channel
                 (->> (random-uuid)
                      (vreset! channel))
                 ;; TODO: remove support for type
                 (doseq [t (if type [type] types)]
                   (register! selector
                              target
                              t
                              (-> x
                                  (dissoc :window/selector)
                                  (assoc :context/x (dissoc x :window/selector)
                                         :window/channel @channel
                                         :context/rf (xf (result-fn))))
                              @channel)))
               (->> (assoc x :window/channel @channel)
                    (rf acc))))))))

;; cljs promises
#?(:cljs
   (defn await-rf [k f]
     (fn [rf]
       (let [once (volatile! nil)
             result (volatile! nil)]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:event/keys [src type]
                  :as x}]
            (if-not @once
              (do
                (vreset! once true)
                (-> (f x)
                    (.then (fn [y]
                             (rf acc (assoc x k y)))))))
            acc))))))



#_(
   *ns*
   (in-ns 'jaq.http.xrf.rf)
   )
