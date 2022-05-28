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

(defn doseq-rf [k xf]
  (fn [rf]
    (let [once (volatile! nil)
          coll (volatile! nil)
          val (volatile! nil)
          vacc (volatile! nil)
          xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (if-not @once
           (do
             (when-not @coll
               (->> (k x)
                    (vreset! coll)))
             (when (seq @coll)
               (->> @coll (assoc x k) (xrf acc))
               (when-let [x' (xrf)]
                 (vswap! coll rest)))
             (if (empty? @coll)
               (do
                 (vreset! once true)
                 (->> (assoc x k @coll)
                      (rf acc)))
               (recur acc x)))
           (->> (assoc x k @coll)
                (rf acc))))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   (into []
         (comp
          identity-rf
          (doseq-rf :coll
                    (comp
                     identity-rf
                     (map (fn [{:keys [coll] :as x}] (prn (first coll)) x)))))
         [{:coll (range 10)}])
   )

;; TODO: does not work w/ cljs async
(defn reduce-rf [acck collk xf]
  (fn [rf]
    (let [once (volatile! nil)
          coll (volatile! nil)
          val (volatile! nil)
          vacc (volatile! nil)
          xrf (xf (result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc x]
         (if-not @once
           (do
             (when-not @coll
               (->> (collk x)
                    (vreset! coll)))
             (when-not @vacc
               (->> (acck x)
                    (vreset! vacc)))
             (when (seq @coll)
               (->> (assoc x
                           acck @vacc
                           collk @coll)
                    (xrf acc))
               (when-let [x' (xrf)]
                 (vswap! coll rest)
                 (vreset! vacc (-> (acck x')))))
             (if (empty? @coll)
               (do
                 (vreset! once true)
                 (->> (assoc x
                             acck @vacc
                             collk @coll)
                      (rf acc)))
               (recur acc x)))
           (->> (assoc x
                       acck @vacc
                       collk @coll)
                (rf acc))))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   (into []
         (comp
          identity-rf
          #_(map (fn [x] (prn x) x))
          (reduce-rf :acc
                     :coll
                     (comp
                      identity-rf
                      (map (fn [{:keys [acc coll] :as x}]
                             (assoc x :acc (+ acc (first coll)))))))
          #_(map (fn [x] (prn x) x)))
         [{:coll (range 10) :acc 0}])

   )

;; TODO: rename to assoc
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
                 #_(prn ::done)
                 (vreset! val x')
                 (vreset! once true)
                 (rf acc (assoc x k x')))
               acc))))))))

(defn assoc-rf [k xf]
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
                 #_(prn ::done)
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
                    (xrf acc x)
                    (catch #?(:cljs js/Error :clj Exception) ex
                      #_(prn ::catch)
                      ex))]
           (cond
             #?(:cljs (instance? e x')
                :clj (instance? e x'))
             (rf acc (f (assoc x :error/exception x')))

             #?(:cljs (instance? js/Error x')
                :clj (instance? Exception x'))
             (throw x')

             :else
             (if-let [x' (xrf)]
               (do
                 (rf acc x'))
               acc)
             )))))))

#_(
   (in-ns 'jaq.http.xrf.rf)
   *e

   :cljs
   (into []
         (catch-rf
          js/Error
          (fn [x] (assoc x :c :nan))
          (comp
           (map (fn [{:keys [a b] :as x}]
                  (throw (js/Error. "error"))
                  #_(assoc x :c (/ a b))))))
         [{:a 4 :b 0} {:a 3 :b 1}])

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

(defn continuation-rf [xf]
  (fn [rf]
    (let [xrf (volatile! nil)
          crf (fn [parent-rf]
                (fn [rf]
                  (fn
                    ([] (rf))
                    ([acc] (rf acc))
                    ([acc x]
                     (parent-rf acc x)))))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host port]
               :as x}]
         (when-not @xrf
           (vreset! xrf ((comp
                          xf
                          (crf rf))
                         (result-fn))))
         (@xrf acc x))))))

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

#?(:cljs
   (defn add-listeners! [selector event-target types]
     (doseq [e types]
       (-> event-target
           (.addEventListener
            (name e)
            (fn [event]
              (let [event-name (-> event (.-constructor) (.-name) (keyword))
                    event-type (-> event (.-type) (keyword))
                    target (-> event (.-target))]
                (when-not (-> @selector
                              (get-in [event-target event-type])
                              (vals))
                  (prn ::event ::no ::listeners event-name event-type target))
                (doseq [{:context/keys [rf acc x cont-rf]
                         {event-once :event/once
                          event-cont :event/cont} :context/x
                         :window/keys [channel]} (-> @selector
                                                     (get-in [event-target event-type])
                                                     (vals))]
                  (prn ::event channel event-name event-type event-once target)
                  (rf acc (assoc x
                                 :context/rf rf
                                 :context/x x
                                 :event/event event
                                 :event/name event-name
                                 :event/type event-type
                                 :event/target target
                                 :window/selector selector
                                 :window/channel channel))
                  (when (or (rf) event-once)
                    (prn ::event ::deregister channel)
                    (deregister! selector event-target event-type channel))))))))))

#_(
   (-> js/ethereum .-on)
   (-> (html/query [:form]) .-addEventListener (type))
   (let [el js/ethereum
         event :chainChanged
         listener (or (. el -addEventListener)
                      (. el -on))]
     (. listener call el (name event) (fn [e] (prn event e))))
   (let [f (. js/ethereum -on)]
     (. f call js/ethereum "chainChanged" (fn [e] (prn e))))


   )

(defn selector! []
  (volatile! {}))

;; TODO: addEventListener to new target
(defn replace! [selector old-target new-target]
  (vswap! selector
          (fn [v o n] (-> v
                          (assoc n (get v o))
                          (dissoc o)))
          old-target new-target))

#_(
   (let [m (volatile! {:target {:type {:channel :x}}})
         target (:target @m)]
     (vswap! m (fn [v o n] (-> v
                               (assoc n (o v))
                               (dissoc o))) :target :target-new)
     )
   )

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



;; TODO: abstract event target to support watching atoms?
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
              (prn ::listeners #_event-target types)
              (add-listeners! selector event-target types)
              (vreset! once true))
            (rf acc x)))))))

#?(:cljs
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
                  (doseq [t types #_(if type [type] types)]
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
                    (doseq [t types #_(if type [type] types)]
                      (prn ::register t @channel)
                       (register! selector
                                 target
                                 t
                                 (-> x
                                     (dissoc :window/selector)
                                     (assoc :context/x (dissoc x :window/selector)
                                            :window/channel @channel
                                            :context/rf (xf (result-fn))))
                                 #_{
                                    :context/x (dissoc x :window/selector :window/channel
                                                       #_:event/target)
                                    :window/channel @channel
                                    :context/rf (xf (result-fn))}
                                 @channel)))
                  (prn ::done ::bind)
                  (->> (assoc x :window/channel @channel)
                       (rf acc)))))))))

#?(:cljs
   (defn watch-rf [xf]
     (fn [rf]
       (let [channel (volatile! nil)]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:event/keys [target]
                  event-once :event/once
                  :as x}]
            (when-not @channel
              (let [xrf (xf (result-fn))]
                (->> (random-uuid)
                     (vreset! channel))
                (->> (fn [ch target before after]
                       ;; TODO: add support for once
                       ;; TODO: remove watch same as select-rf
                       (xrf acc (assoc x
                                       :event/target target
                                       :event/before before
                                       :event/after after
                                       :window/channel ch))
                       (when (or (xrf) event-once)
                         (.setTimeout js/window
                                      (fn []
                                        (prn ::removing @channel)
                                        (remove-watch target @channel)) 0)))
                     (add-watch target @channel))))
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
                             (rf acc (assoc x k y))))
                    (.catch (fn [y]
                              (rf acc (assoc x :error/error y)))))))
            acc))))))

#?(:cljs
   (defn async-rf [xf]
     (fn [rf]
       (let [promise (volatile! nil)
             xrf (xf (result-fn))]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:event/keys [src type]
                  :as x}]
            (when-not @promise
              (->> (xrf acc (assoc x
                                   :context/rf xrf
                                   :context/x x))
                   (vreset! promise)))
            (->> (assoc x :async/promise xrf)
                 (rf acc))))))))

#?(:cljs
   (defn defer-rf [xf]
     (fn [rf]
       (let [deferred (volatile! nil)
             xrf (xf (result-fn))]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:event/keys [src type timeout]
                  :or {timeout 0}
                  :as x}]
            (when-not @deferred
              (->> (fn []
                     (xrf acc (assoc x
                                     :context/rf xrf
                                     :context/x x)))
                   (vreset! deferred))
              (.setTimeout js/self @deferred timeout))
            (->> (assoc x :async/deferred @deferred)
                 (rf acc))))))))

#?(:cljs
   (defn schedule-rf [xf]
     (fn [rf]
       (let [deferred (volatile! nil)
             d (volatile! nil)
             defer-fn (fn [t]
                        #_(prn ::scheduling t)
                        (.setTimeout js/window @deferred t))
             xrf (xf (result-fn))]
         (fn
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:event/keys [timeout timeout-fn]
                  :or {timeout 100
                       timeout-fn (fn [t] (* 2 t))}
                  :as x}]
            (when-not @deferred
              (vreset! d timeout)
              (->> (fn []
                     (xrf acc (assoc x
                                     :event/timeout @d
                                     :context/rf xrf
                                     :context/x x))
                     (if-let [x' (xrf)]
                       (rf acc x')
                       (->> timeout-fn
                            (vswap! d)
                            (defer-fn))))
                   (vreset! deferred))
              #_(@deferred)
              (defer-fn timeout))
            acc))))))

#_(
   (def state (volatile! []))
   (into []
         (comp
          (schedule-rf (comp
                        (map (fn [{:context/keys [state]
                                   :event/keys [timeout]
                                   :as x}]
                               (prn timeout)
                               (vswap! state conj timeout)
                               x))
                        (drop-while (fn [{:event/keys [timeout]}]
                                      (< timeout 500)))))
          (map (fn [{:context/keys [state] :as x}]
                 (vswap! state conj :end)
                 x))
          (drop-while (fn [_] true)))
         [{:event/timeout 100
           :context/state (volatile! nil) #_state}])
   @state

   )

;; persist rfs

#_(

   ;; idea: overload with 3rd arg

   *e
   (let [acc []
         result (volatile! nil)
         pf (fn [rf]
              (fn
                ([] (rf))
                ([acc] acc)
                ([acc m] (rf acc m))
                ([acc m {:persist/keys [cmd file] :as p}]
                 (prn ::p p)
                 (cond
                   (= cmd :persist/load)
                   (->> (slurp file)
                        (clojure.edn/read-string)
                        (merge p)
                        (rf acc m))
                   :else
                   (rf acc m p)))))
         rf (fn
              ([] @result)
              ([acc] acc)
              ([acc m] (vswap! result conj m) acc)
              ([acc m {:persist/keys [cmd file pfn] :as p}]
               (cond
                 (= cmd :persist/save)
                 (pfn p)
                 :else
                 p)))
         xf (comp
             pf
             (fn [rf]
               (let [i (volatile! -1)]
                 (fn
                   ([] (rf))
                   ([acc] (rf acc))
                   ([acc m]
                    (->> (vswap! i inc)
                         (assoc m :context/index)
                         (rf acc)))
                   ([acc m {:persist/keys [cmd]
                            persisted-i :index/i
                            :as p}]
                    (prn ::xf p)
                    (cond
                      (= cmd :persist/save)
                      (->> (assoc p :index/i @i)
                           (rf acc m))
                      (= cmd :persist/load)
                      (do
                        (prn ::loading persisted-i)
                        (vreset! i persisted-i)
                        (rf acc m p))))))))
         p {:persist/cmd :persist/save
            :persist/file "rf.edn"
            :persist/pfn (fn [{:persist/keys [file] :as p}] (->> (dissoc p :persist/pfn :persist/cmd)
                                                                 (pr-str) (spit file)))}
         xrf (xf rf)]
     (doseq [m (->> (range 10) (map (fn [e] {:context/n e})))]
       (xrf acc m))
     ;; persist rf
     (xrf nil nil p)
     ;; recover
     (let [yrf (xf rf)]
       (->> (assoc p :persist/cmd :persist/load)
            (yrf nil nil))
       (doseq [m (->> (range 10) (map (fn [e] {:context/n e})))]
         (yrf acc m))
       (yrf))
     #_(xrf))

   *e


   )


#_(
   *ns*
   (in-ns 'jaq.http.xrf.rf)
   )
