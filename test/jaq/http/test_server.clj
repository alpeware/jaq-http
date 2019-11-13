(ns jaq.http.test-server
  (:require
   [clojure.test :refer :all]
   [jaq.http.server :as server]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.rf :as rf]))

(defn sut [f]
  (let [xrf app/echo
        {:keys [shutdown-fn] :as s} (server/serve xrf 8080)]
    (f)
    (shutdown-fn)
    (-> s :future (deref))
    (prn ::done)))

;; TODO: doesn't shutdown immediately
#_(use-fixtures :once sut)

#_(deftest test-echo-server
  (let [s (slurp "http://localhost:8080")]
    (is (= "echo" s))))
