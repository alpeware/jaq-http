(ns jaq.http.xrf.test-header
  (:require
   [clojure.test.check :as tc]
   [clojure.test.check.clojure-test :refer [defspec]]
   [clojure.test.check.generators :as gen]
   [clojure.test.check.properties :as prop]
   [clojure.test :refer :all]
   [com.gfredericks.test.chuck.clojure-test :refer [for-all]]
   [com.gfredericks.test.chuck :as chuck]
   [taoensso.tufte :as tufte]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.rf :as rf])
  (:import
   [java.net URLDecoder URLEncoder]
   [java.nio.charset StandardCharsets]))

(defn run [xform buf]
  (let [xf ((comp
             rf/index
             xform) (rf/result-fn))]
    (run! (fn [x] (xf nil x)) buf)
    (xf)))

(deftest test-request-line-basic
  (let [buf "GET / HTTP/1.1\r\n "
        xform header/request-line]
    (let [{:keys [method path scheme minor major] :as m} (run xform buf)]
      (is (= method :GET))
      (is (= path "/"))
      (is (= major 1))
      (is (= minor 1))
      (is (= scheme "HTTP")))))

(deftest test-request-query
  (let [buf "?foo=&baz=bazz "
        xform (comp
               rf/index
               header/query)]
    (let [{:keys [params] :as m} (->> (sequence xform buf) (first))]
      (is (= params {:foo nil :baz "bazz"})))))

(defspec check-request-query 100
  (for-all [original (gen/let [ms (-> (fn [[k v]]
                                        {k (if (clojure.string/blank? v) nil v)})
                                      (gen/fmap
                                       (gen/tuple gen/keyword
                                                  gen/string-alphanumeric))
                                      (gen/vector))]
                       (apply merge ms))]
           (let [encode-fn (fn [s]
                             (if (nil? s)
                               nil
                               (URLEncoder/encode s (.name params/default-charset))))
                 encoded (->> original
                              (map (fn [[k v]]
                                     (str (encode-fn (name k))
                                          "=" (encode-fn v))))
                              (clojure.string/join "&"))
                 xform (comp
                        jaq.http.xrf.rf/index
                        header/query)
                 buf (str "?" encoded " ")
                 decoded (->> (sequence xform buf) (first) :params)]
             (is (= original decoded)))))

#_(
   *e
   (run-tests)
   )

(deftest test-request-line-fragment
  (let [buf "GET /#foo HTTP/1.1\r\n "
        xform header/request-line]
    (let [{:keys [fragment] :as m} (run xform buf)]
      (is (= fragment "#foo")))))

(deftest test-headers-basic
  (let [buf "Host: alpeware\r\nContent-Type: plain/text\r\n\r\n"
        xform header/headers]
    (let [{{:keys [host content-type]} :headers :as m} (run xform buf)]
      (is (= host "alpeware"))
      (is (= content-type "plain/text")))))

(deftest test-headers-whitespace
  (let [buf "Custom: foo bar baz\r\n\r\n"
        xform header/headers]
    (let [{{:keys [custom]} :headers :as m} (run xform buf)]
      (is (= custom "foo bar baz")))))

(deftest test-headers-content-length
  (let [buf "Content-Length: 123\r\n\r\n"
        xform header/headers]
    (let [{{:keys [content-length]} :headers :as m} (run xform buf)]
      (is (= content-length 123)))))


#_(
   *e
   *ns*
   (require 'jaq.http.xrf.test-header :reload)
   (in-ns 'jaq.http.xrf.test-header)
   ;; run all tests
   (run-tests)

   ;; list vars
   (->> *ns*
        (ns-publics)
        (keys))

   ;; unmap var
   (ns-unmap *ns* 'test-request-line-query)

   )
