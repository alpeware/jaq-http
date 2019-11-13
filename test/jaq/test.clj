(ns jaq.test
  (:require
   [clojure.test :refer :all]
   [jaq.http.xrf.test-header]))

(defn -main [& args]
  (run-all-tests #"jaq.*"))
