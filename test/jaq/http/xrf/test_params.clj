(ns jaq.http.xrf.test-params
  (:require
   [clojure.test :refer :all]
   [clojure.test.check :as tc]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [taoensso.tufte :as tufte]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.net URLDecoder URLEncoder]
   [java.nio.charset StandardCharsets]))

(def utf-8 (.name StandardCharsets/UTF_8))

(defn run [xform buf]
  (let [xf ((comp
             rf/index
             xform) (rf/result-fn))]
    (run! (fn [x] (xf nil x)) buf)
    (xf)))

(deftest test-decode
  (let [original "foo bar &$! s"
        encoded (URLEncoder/encode original utf-8)
        xform (comp
               rf/index
               (map (fn [x]
                      (assoc! x :headers {:content-length (count encoded)})))
               params/decode)]
    (let [decoded (->> (sequence xform encoded)
               (map :char)
               (apply str))]
      (is (= original decoded)))))

#_(
   *e
   *ns*
   (in-ns 'jaq.http.xrf.test-params)
   ;; run all tests
   (run-tests)

   )
