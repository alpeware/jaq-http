(ns jaq.http.xrf.app
  (:require
   [clojure.core.async :as async]
   [clojure.edn :as edn]
   [clojure.string :as string]
   [clojure.java.io :as io]
   [clojure.walk :as walk]
   [jaq.repl :as r]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.rf :as rf]
   [net.cgrand.xforms :as x])
  (:import
   [java.util UUID Locale]))

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(defn uuid []
  (->
   (UUID/randomUUID)
   (str)
   (keyword)))

(def counter
  (let [cnt (volatile! 0)]
    (map (fn [e]
           (-> e
               (assoc :app/counter (vswap! cnt inc))
               (assoc :app/uuid (uuid)))))))

(def main
  (comp
   rf/index
   header/request-line
   header/headers
   (map (fn [x]
          (def x x)
          x))
   (comp
    (x/multiplex
     [(comp
       (filter (fn [{:keys [path]}]
                 (= path "/repl")))
       (filter (fn [{:keys [method]}]
                 (= method :POST)))
       (filter (fn [{{:keys [content-type]} :headers}]
                 (= content-type "application/x-www-form-urlencoded")))
       #_(map (fn [x]
              (prn x)
                x))
       (drop 1)
       params/params
       #_(map (fn [x]
              (prn x)
              x))
       (rf/branch (fn [{{input :form session-id :device-id :keys [repl-token]} :params}]
                    (and (= repl-token (or (:JAQ-REPL-TOKEN env) "foobarbaz"))))
                  (comp
                   (map (fn [{{input :form session-id :device-id :keys [repl-token]} :params
                              :keys [headers]}]
                          (->> {:input input :session-id session-id}
                               (r/session-repl)
                               ((fn [{:keys [val ns ms]}]
                                  {:status 200
                                   :headers headers
                                   :body (str ns " => " val " - " ms "ms" "\n")}))))))
                  (comp
                   (map (fn [{:keys [uuid]}]
                          {:status 403
                           :headers {}
                           :body "Forbidden"})))))
      (comp
       (filter (fn [{:keys [path]}]
                 (= path "/")))
       counter
       #_(map (fn [x]
              (prn x)
              x))
       (map (fn [{:app/keys [uuid counter]}]
              {:status 200
               :headers {}
               :body (str "You are visitor " counter ".")})))
      (comp
       (filter (fn [{:keys [path]}]
                 (= path "/_ah/warmup")))
       (map (fn [x]
              (prn ::warmup x)
              x))
       (map (fn [{:app/keys [uuid counter]
                  {:keys [host]} :headers}]
              {:status 200
               :headers {:host host}
               :body ""})))
      (comp
       (filter (fn [{:keys [path]}]
                 (and (not= path "/")
                      (not= path "/repl"))))
       (map (fn [{:app/keys [uuid counter]
                  {:keys [host]} :headers}]
              {:status 404
               :headers {:host host}
               :body ""})))]))))

#_(
   (in-ns 'jaq.http.xrf.app)
   *e
   x
   )
