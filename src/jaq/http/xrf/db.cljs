(ns jaq.http.xrf.db
  (:require
   [clojure.string :as string]
   [jaq.http.xrf.rf :as rf]))

;; indexedDB rfs

;; simple k/v store
(def open-db-rf
  (comp
   (rf/one-rf :db/request
              (comp
               (map (fn [{:db/keys [name version] :as x}]
                      (assoc x
                             :db/request (.open js/window.indexedDB (str name) version))))
               (map :db/request)))
   (map (fn [{:db/keys [request] :as x}]
          (assoc x
                 :event/target request
                 :event/types [:error :success :blocked :upgradeneeded])))
   rf/select-rf
   ;; TODO: schema for a simple k/v store
   (map (fn [{:db/keys [request] :as x}]
          (assoc x
                 :event/target request
                 :event/types [:upgradeneeded])))
   (rf/bind-rf (comp
                (map (fn [{:event/keys [event target] :as x}]
                       (assoc x :db/db (.-result target))))
                (map (fn [{:db/keys [db store options] :as x}]
                       (.createObjectStore db (str store) (clj->js options))
                       x))))
   ;; DB open or error
   (map (fn [{:db/keys [request] :as x}]
          (assoc x
                 :event/target request
                 :event/types [:error :success])))
   (rf/bind-rf)
   (rf/choose-rf :event/type
                 {:error (comp
                          (map (fn [{:event/keys [event target] :as x}]
                                 (.info js/console event)
                                 (assoc x :error/error (.-error target)))))
                  :success (comp
                            (rf/one-rf :db/db
                                       (comp
                                        (map (fn [{:event/keys [target] :as x}]
                                               (assoc x
                                                      :db/db (.-result target))))
                                        (map :db/db))))})))

(def close-db-rf
  (rf/once-rf (fn [{:db/keys [db] :as x}]
                (-> db (.close))
                x)))

(def get-rf
  (comp
   (map (fn [{:db/keys [transaction store]
              db-key :db/key
              :as x}]
          (prn ::db ::get store db-key)
          (assoc x
                 :db/request (try
                               (-> transaction
                                   (.objectStore store)
                                   (.get (str db-key)))
                               (catch :default e
                                 (prn ::db ::error e)
                                 e)))))
   (map (fn [{:db/keys [request] :as x}]
          (assoc x
                 :event/target request
                 :event/types [:success])))
   rf/select-rf
   (rf/bind-rf)
   (map (fn [{:event/keys [target] :as x}]
          (assoc x :db/value (.-result target))))))

(def put-rf
  (comp
   (map (fn [{:db/keys [transaction store value]
              db-key :db/key
              :as x}]
          (prn ::db ::put store db-key value)
          #_(.info js/console transaction)
          (assoc x
                 :db/request (try
                               (-> transaction
                                   (.objectStore store)
                                   (.put (clj->js value) (str db-key))
                                   #_(.put value (str db-key)))
                               (catch :default e
                                 (prn ::db ::error e)
                                 e)))))
   (map (fn [{:db/keys [request] :as x}]
          (assoc x
                 :event/target request
                 :event/types [:success])))
   rf/select-rf
   (rf/bind-rf)))


;; get or upsert
(def gupsert-rf
  (comp
   get-rf
   (rf/choose-rf (fn [{:db/keys [value] :as x}]
                   (some? value))
                 {false (comp
                         (map (fn [{:db/keys [default] :as x}]
                                (assoc x :db/value default)))
                         put-rf)
                  true (comp
                        (map (fn [{:db/keys [value] :as x}]
                               x
                               #_(assoc x :db/value (-> value
                                                      (fress/create-reader)
                                                      (fress/read-object))))))})))

(defn transact-rf [xf]
  (fn [rf]
    (let [xrf (xf (rf/result-fn))
          yrf ((comp
                (rf/one-rf :db/transaction
                           (comp
                            (map (fn [{:db/keys [db store mode] :as x}]
                                   (prn ::db db)
                                   (assoc x :db/transaction (-> db (.transaction [store] (name mode))))))
                            (map (fn [{:db/keys [transaction] :as x}]
                                   (assoc x
                                          :event/target transaction
                                          :event/types [:error :complete :abort])))
                            rf/select-rf
                            (map :db/transaction)))
                (map (fn [{:db/keys [transaction] :as x}]
                       (prn ::tx transaction)
                       (-> x
                           (dissoc :event/type)
                           (assoc :event/target transaction
                                  :event/types [:error :complete :abort]))))
                (rf/bind-rf (fn [zrf]
                              (fn
                                ([] (zrf))
                                ([acc] (zrf acc))
                                ([acc y]
                                 (rf acc (xrf)))))))
               (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:db/keys [db store mode] :as x}]
         (yrf acc x)
         (xrf acc (yrf))
         acc)))))


#_(

   (->> (yrf) :event/type)
   (->> y :window/selector (deref) (keys))
   (into []
         (comp
          rf/selector-rf
          open-db-rf
          (transact-rf (comp
                        (map (fn [{:rtc/keys [certificate] :as x}]
                               (def y x)
                               (assoc x
                                      :db/key :device/uuid)))
                        get-rf))
          (map (fn [{:db/keys [key value]
                     :crypto/keys [jwt]
                     :as x}]
                 (def y x)
                 (prn ::jwt jwt)
                 (prn ::get key value)
                 x))
          close-db-rf
          (drop-while (constantly true)))
         [{:db/name :fpp/db
           :db/version 1
           :db/store :fpp/cache
           :db/mode :readwrite
           :db/options {}}])

   (-> y (keys))
   (yrf)

   )
