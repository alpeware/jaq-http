(ns jaq.http.xrf.test-json
  (:require
   [clojure.data.json :as clj-json]
   [clojure.string :as string]
   [clojure.test :refer :all]
   [clojure.test.check :as tc]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [com.gfredericks.test.chuck.clojure-test :refer [for-all]]
   [com.gfredericks.test.chuck :as chuck]
   [taoensso.tufte :as tufte]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.nio.charset StandardCharsets]))

(defspec check-decode 100
  (for-all [original gen/string]
           (let [encoded (->> (clj-json/write-str [original])
                              (drop 2)
                              (drop-last 2)
                              (apply str))
                 xform (comp
                        rf/index
                        (json/decoder))
                 decoded (->> (sequence xform encoded)
                              (map :char)
                              (map (fn [c] (if (= c :quotes) \" c)))
                              (apply str))]
             (is (= original decoded)))))

#_(

   (in-ns 'jaq.http.xrf.test-json)
   (clj-json/write-str [:foo])

   (let [original (-> (gen/sample gen/string) last)
         s (->> (clj-json/write-str [original]))
         j (->> (clj-json/read-str s) (first))
         encoded (->> s (drop 2) (drop-last 2) (apply str))
         xform (comp
                rf/index
                (json/decoder))
         decoded (->> (sequence xform encoded)
                      (map :char)
                      (apply str))]
     [original encoded decoded j (= original j) (= original decoded)])

   (let [;;original "J"
         original "\""
         s (->> (clj-json/write-str [original]))
         j (->> (clj-json/read-str s) (first))
         encoded (->> s (drop 2) (drop-last 2) (apply str))
         ;;encoded "\\u007f"
         xform (comp
                rf/index
                (json/decoder))
         decoded (->> (sequence xform encoded)
                      (map :char)
                      (map (fn [c] (if (= c :quotes) \" c)))
                      (apply str))]
     [original encoded decoded j (= original j) (= original decoded)])

   )

(defspec check-process-simple-maps 100
  (for-all [original (gen/let [ms (-> (fn [[k v]]
                                        {k v})
                                      (gen/fmap
                                       (gen/tuple gen/keyword
                                                  gen/string-alphanumeric))
                                      (gen/vector))]
                       (apply merge ms))]
           (let [encoded (clj-json/write-str original)
                 xform (comp
                        rf/index
                        (json/decoder)
                        (json/process))
                 decoded (->> (sequence xform encoded) (first) :json)]
             (is (= original decoded)))))

(defspec check-process-simple-arrays 100
  (for-all [original (gen/vector (gen/tuple
                                  gen/nat
                                  gen/boolean
                                  (gen/double* {:infinite? false :NaN? false})
                                  gen/string))]
           (let [encoded (clj-json/write-str original)
                 xform (comp
                        rf/index
                        (json/decoder)
                        (json/process))
                 decoded (->> (sequence xform encoded) (first) :json)]
             (is (= original decoded)))))

#_(

   (gen/sample (gen/vector (gen/tuple gen/nat gen/boolean gen/double gen/string)))

   )

(defspec check-process-nested-mixed 100
  (for-all [original (gen/recursive-gen
                      (fn [inner-gen]
                        (gen/one-of [(gen/vector inner-gen)
                                     (gen/map gen/keyword inner-gen)]))
                      (gen/one-of [gen/nat (gen/double* {:infinite? false :NaN? false}) gen/boolean gen/string]))]
           (let [original (if-not (or (vector? original) (map? original)) [original] original)
                 encoded (clj-json/write-str original)
                 xform (comp
                        rf/index
                        (json/decoder)
                        (json/process))
                 decoded (->> (sequence xform encoded) (first) :json)]
             (is (= original decoded)))))

#_(

   (let [json (gen/recursive-gen
               (fn [inner-gen]
                 (gen/one-of [(gen/vector inner-gen)
                              (gen/map gen/keyword inner-gen)]))
               (gen/one-of [gen/nat (gen/double* {:infinite? false :NaN? false}) gen/boolean gen/string]))
         original (->>
                   (gen/sample json 20)
                   (last))
         original (if-not (or (vector? original) (map? original)) [original] original)
         encoded (clj-json/write-str original)
         xform (comp
                rf/index
                (json/decoder)
                (json/process))
         decoded (->> (sequence xform encoded) (first) :json)]
     [original encoded decoded (= original decoded)])

   (tufte/add-basic-println-handler! {})
   (tufte/profile
    {:id :json}
    (let [json (gen/recursive-gen
                (fn [inner-gen]
                  (gen/one-of [(gen/vector inner-gen)
                               (gen/map gen/keyword inner-gen)]))
                (gen/one-of [gen/nat (gen/double* {:infinite? false :NaN? false}) gen/boolean gen/string]))
          xform (comp
                 rf/index
                 (json/decoder)
                 (json/process))]
      (doseq [original (gen/sample json 400)]
        (let [original (if-not (or (vector? original) (map? original)) [original] original)
              encoded (clj-json/write-str original)]
          (tufte/p ::jaq (->> (sequence xform encoded) (first) :json))
          (tufte/p ::data (clj-json/read-str encoded))))))


   *e
   *ns*
   (require 'jaq.http.xrf.test-json :reload)
   (in-ns 'jaq.http.xrf.test-json)
   ;; run all tests
   (run-tests)

   (ns-publics *ns*)
   (ns-unmap *ns* 'check-process)
   )