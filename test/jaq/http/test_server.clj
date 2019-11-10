(ns jaq.http.test-server
  (:require
   [clojure.core.async :as async]
   [clojure.test :refer :all]
   [jaq.http.server :as server]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.rf :as rf]))

(defn sut [f]
  (let [xrf (comp
             rf/index
             header/request-line
             header/headers
             (map (fn [{:keys [path method]}]
                    {:status 200 :headers {} :body (str method)})))
        {:keys [shutdown] :as s} (server/serve xrf 8080)]
    (f)
    (async/>!! shutdown :shutdown)))

(use-fixtures :once sut)

(deftest test-echo-server
  (with-redefs [jaq.http.server.nio/*app-xrf* (comp
                                                 rf/index
                                                 header/request-line
                                                 header/headers
                                                 (map (fn [{:keys [path method]}]
                                                        {:status 200 :headers {} :body "FOO"})))]
    (let [s (slurp "http://localhost:8080")]
      (prn s)
      (is (= ":GET" s)))))


(defn -main [& args]
  (run-tests 'jaq.http.test-server))
