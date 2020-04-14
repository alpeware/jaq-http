(ns jaq.http.xrf.server
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]
   [jaq.repl :as r]
   [net.cgrand.xforms :as x]))

(defn server-rf [xf]
  (comp
   nio/selector-rf
   (nio/thread-rf
    (comp
     nio/attachment-rf
     nio/bind-rf
     (nio/accept-rf xf)
     nio/select-rf
     nio/close-rf))))

(def response-rf
  (comp
   (map (fn [x] (assoc x :http/req [])))
   (map (fn [{:http/keys [req headers host] :as x}]
          (assoc x :http/headers (conj {:Host host} headers))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "HTTP")))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "/")))
   (map (fn [{:http/keys [req major minor] :as x}]
          (update x :http/req conj (str major "." minor))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj " ")))
   (map (fn [{:http/keys [req major status reason] :as x}]
          (update x :http/req conj (str status " " reason))))
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "\r\n")))
   (map (fn [{:http/keys [headers body] :as x}]
          (cond
            (not body)
            (update x :http/headers conj {:content-length 0})

            (string? body)
            (update x :http/headers conj {:content-length (count body)})

            (instance? java.nio.ByteBuffer body)
            (update x :http/headers conj {:content-length (.limit body)}))))
   http/headers-rf
   (map (fn [{:http/keys [req] :as x}]
          (update x :http/req conj "\r\n")))
   (map (fn [{:http/keys [req body] :as x}]
          (if body
            (update x :http/req conj body)
            x)))))

(def repl-rf
  (comp
   nio/attachment-rf
   nio/valid-rf
   nio/read-rf
   nio/write-rf
   (rf/repeatedly-rf
    (comp
     (nio/receive-rf
      (comp
       (rf/one-rf
        :http/request
        (comp
         (map (fn [{:keys [byte] :as x}]
                (assoc x :char (char byte))))
         header/request-line
         header/headers))
       (map (fn [{{:keys [headers status path method]} :http/request
                  :as x}]
              (assoc x
                     :method method
                     :path path
                     :headers headers
                     :status status)))
       (rf/choose-rf
        :path
        {"/repl" (comp
                  (map (fn [{:keys [byte] :as x}]
                         (assoc x :char (char byte))))
                  (drop 1)
                  params/body
                  (rf/branch (fn [{:keys [method]
                                   {:keys [content-type]} :headers
                                   {input :form session-id :device-id :keys [repl-token]} :params}]
                               (and
                                (= content-type "application/x-www-form-urlencoded")
                                (= method :POST)
                                (= repl-token (or #_(:JAQ-REPL-TOKEN env) "foobarbaz"))))
                             (comp
                              (map (fn [{{input :form session-id :device-id :keys [repl-token]} :params
                                         :keys [headers] :as x}]
                                     (->> {:input input :session-id session-id}
                                          (jaq.repl/session-repl)
                                          ((fn [{:keys [val ns ms]}]
                                             (assoc x
                                                    :http/status 200
                                                    :http/reason "OK"
                                                    :http/headers {:content-type "text/plain"
                                                                   :connection "keep-alive"}
                                                    :http/body (str ns " => " val " - " ms "ms" "\n"))))))))
                             (comp
                              (map (fn [{:keys [uuid] :as x}]
                                     (assoc x
                                            :http/status 403
                                            :http/reason "FORBIDDEN"
                                            :http/headers {:content-type "text/plain"
                                                           :connection "keep-alive"}
                                            :http/body "Forbidden"))))))
         "/" (map (fn [{:app/keys [uuid]
                        {:keys [x-appengine-city
                                x-appengine-country
                                x-appengine-region
                                x-appengine-user-ip
                                x-cloud-trace-context]} :headers
                        :as x}]
                    (assoc x
                           :http/status 200
                           :http/reason "OK"
                           :http/headers {:content-type "text/plain"
                                          :connection "keep-alive"}
                           :http/body (str "You are from " x-appengine-city " in "
                                           x-appengine-region " / " x-appengine-country "."
                                           " Your IP is " x-appengine-user-ip " and your trace is "
                                           x-cloud-trace-context "."))))
         :default (map (fn [{:app/keys [uuid]
                             {:keys [host]} :headers
                             :as x}]
                         (assoc x
                                :http/status 404
                                :http/reason "NOT FOUND"
                                :http/headers {:content-type "text/plain"
                                               :connection "keep-alive"}
                                :http/body "NOT FOUND")))})))
     response-rf
     nio/send-rf
     (map (fn [{:nio/keys [^SelectionKey selection-key] :as x}]
            (nio/readable! selection-key)
            x))))))

#_(
   *ns*
   *e
   (in-ns 'jaq.http.xrf.server)
   )
