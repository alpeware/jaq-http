(ns jaq.http.xrf.test-params
  (:require
   [clojure.test :refer :all]
   [clojure.test.check :as tc]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [com.gfredericks.test.chuck.clojure-test :refer [for-all]]
   [com.gfredericks.test.chuck :as chuck]
   [taoensso.tufte :as tufte]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.net URLDecoder URLEncoder]
   [java.nio.charset StandardCharsets]))

(defspec check-decode 100
  (for-all [original gen/string]
           (let [encoded (URLEncoder/encode original (.name params/default-charset))
                      xform (comp
                             rf/index
                             (map (fn [x]
                                    (assoc x :headers {:content-length (count encoded)})))
                             (params/decoder))
                      decoded (->> (sequence xform encoded)
                                   (map :char)
                                   (apply str))]
                  (is (= original decoded)))))

(defspec check-params 100
  (for-all [original (gen/let [ms (-> (fn [[k v]]
                                             {k (if (clojure.string/blank? v) nil v)})
                                           (gen/fmap
                                            (gen/tuple gen/keyword
                                                       gen/string-alphanumeric))
                                           (gen/vector))]
                            (apply merge ms))]
                (let [encoded (->> original
                                   (map (fn [[k v]] (str (name k) "=" v)))
                                   (clojure.string/join "&"))
                      xform (comp
                             jaq.http.xrf.rf/index
                             (map (fn [{:keys [char] :as x}]
                                    (assoc x :char
                                           (condp = char
                                             \= :assign
                                             \& :sep
                                             char))))
                             (map (fn [{:keys [index] :as x}]
                                    (if (= index (-> encoded (count) (dec)))
                                      (assoc x :eob true)
                                      x)))
                             params/params)
                      decoded (->> (sequence xform encoded) (first) :params)]
                  (is (= original decoded)))))

#_(
   *e
   *ns*
   (require 'jaq.http.xrf.test-params :reload)
   (in-ns 'jaq.http.xrf.test-params)
   ;; run all tests
   (run-tests)

   (ns-publics *ns*)
   (ns-unmap *ns* 'test-decode)
   )
