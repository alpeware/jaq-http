(ns jaq.http.xrf.test-header
  (:require
   [clojure.test :refer :all]
   [taoensso.tufte :as tufte]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.rf :as rf]))

#_(
   (let [buf "GET / HTTP/1.1\r\n "
         rf (let [result (volatile! nil)]
              (fn
                ([] @result)
                ([acc] acc)
                ([acc x] (vreset! result (persistent! x)) acc)))
         xform (comp
                rf/index
                request-line)
         xf (xform rf)]
     (run! (fn [x] (tufte/p :xf (xf nil x))) buf)
     (rf)))

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

(deftest test-request-line-query
  (let [buf "GET /?foo HTTP/1.1\r\n "
        xform header/request-line]
    (let [{:keys [query] :as m} (run xform buf)]
      (is (and
           (= query "foo"))))))

;;TODO: add query params

(deftest test-request-line-fragment
  (let [buf "GET /#foo HTTP/1.1\r\n "
        xform header/request-line]
    (let [{:keys [fragment] :as m} (run xform buf)]
      (is (and
           (= fragment "foo"))))))

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
   (in-ns 'jaq.http.xrf.test-header)
   ;; run all tests
   (run-tests)

   ;; list vars
   (->> *ns*
        (ns-publics)
        (keys))

   ;; unmap var
   (ns-unmap *ns* 'test-request-line)

   )
