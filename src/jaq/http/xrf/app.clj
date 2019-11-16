(ns jaq.http.xrf.app
  (:require
   [clojure.walk :as walk]
   [jaq.repl :as r]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.response :as response]
   [jaq.http.xrf.rf :as rf]
   [taoensso.tufte :as tufte]
   [net.cgrand.xforms :as x])
  (:import
   [java.util UUID]))

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(defn uuid []
  (->
   (UUID/randomUUID)
   (str)
   (keyword)))

(def http
  (comp
   rf/index
   header/request-line
   header/headers))

(def echo
  (comp
   rf/index
   header/request-line
   header/headers
   (map (fn [x]
          {:status 200 :headers {} :body "echo"}))
   response/plain))

#_(
   (in-ns 'jaq.http.xrf.app)
   (tufte/profile
    {}
    (let [buf "GET / HTTP/1.1\r\nHost: jaq\r\n\r\n"
          rf (let [result (volatile! nil)]
               (fn
                 ([] @result)
                 ([acc] acc)
                 ([acc x] (vreset! result x) acc)))
          xf (echo rf)]
      (run! (fn [x] (tufte/p :xf (xf nil x))) buf)
      (rf)))
   *e
   )

(def repl
  (comp
   rf/index
   header/request-line
   header/headers
   (x/multiplex
    [(comp
      (filter (fn [{:keys [path]}]
                (= path "/repl")))
      (filter (fn [{:keys [method]}]
                (= method :POST)))
      (filter (fn [{{:keys [content-type]} :headers}]
                (= content-type "application/x-www-form-urlencoded")))
      (drop 1)
      params/body
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
                (= path "/_ah/warmup")))
      (map (fn [{:app/keys [uuid]
                 {:keys [host]} :headers}]
             {:status 200
              :headers {}
              :body "OK"})))
     (comp
      (filter (fn [{:keys [path]}]
                (= path "/")))
      (map (fn [{:app/keys [uuid]
                 {:keys [x-appengine-city
                         x-appengine-country
                         x-appengine-region
                         x-appengine-user-ip
                         x-cloud-trace-context]} :headers}]
             {:status 200
              :headers {}
              :body (str "You are from " x-appengine-city " in "
                         x-appengine-region " / " x-appengine-country "."
                         " Your IP is " x-appengine-user-ip " and your trace is "
                         x-cloud-trace-context ".")})))])
   response/plain))

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
