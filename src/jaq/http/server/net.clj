(ns jaq.http.server.net
  (:gen-class)
  (:require
   [clojure.core.async :as async]
   [clojure.string :as string]
   [clojure.java.io :as io]
   [clojure.walk :as walk]
   [jaq.http.xrf.app :as app])
  (:import
   [java.io IOException]
   [java.net ServerSocket SocketException]
   [java.nio.charset StandardCharsets Charset]
   [java.time.format DateTimeFormatter]
   [java.time ZonedDateTime ZoneId]))

(def ^:dynamic *http-server* nil)

(def ^:dynamic *app-xrf* nil)

(def ^:dynamic *chan-buf* 1)

(def buffer-size (* 256 1024))

(def charset StandardCharsets/UTF_8)

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(def pattern (DateTimeFormatter/ofPattern "EEE, dd MMM yyyy HH:mm:ss zzz"))

(def zone (ZoneId/of "GMT"))

(defn now []
  (-> zone
      (ZonedDateTime/now)
      (.format pattern)))

(def port (or (some-> env :PORT (Integer/parseInt))
              3000))

(defn response [{:keys [status headers body]}]
  (->> ["HTTP/1.1" " " status " " "OK" "\r\n"
        "Date:" " " (now) "\r\n"
        ;;"Host:" " " (:host headers) "\r\n"
        ;;"Server:" " alpeware/jaq" "\r\n"
        "Content-Type: text/plain" "\r\n"
        "Connection: close" "\r\n"
        ;;"Content-Length: " (count body) "\r\n"
        "\r\n"
        body]
       (apply str)))

(defn connection [client]
  (let [in (io/reader (.getInputStream client))
        out (io/writer (.getOutputStream client))
        ch (async/chan *chan-buf* *app-xrf* (fn [e] (prn ::exception e) {:exception e}))]

    ;; req
    (let [buf (char-array buffer-size)]
      (async/go-loop []
        (let [n (try
                  (.read in buf)
                  (catch SocketException e
                    -1)
                  (catch IOException e
                    -1))]
          (if (< n 0)
            (do
              (.close in))

            (do
              (async/onto-chan ch (char-array n buf) false)
              (recur))))))

    ;; res
    (async/go
      (let [res (async/<! ch)
            buf (-> res
                     (response)
                     #_(.getBytes charset)
                     (char-array))]
        (async/close! ch)
        (try
          (.write out buf)
          (.close out)
          (.close in)
          (.close client)
          (catch SocketException e
            e)
          (catch IOException e
            e))))))

(defn serve [xrf p]
  (let [server (ServerSocket. p)]
    (prn ::starting ::port p)
    ;; app
    (alter-var-root #'*app-xrf* (constantly xrf))
    (->>
     (async/go-loop []
       (when-let [client (async/<! (async/thread (.accept server)))]
         (connection client)
         (recur)))
     (conj [:server server :chan])
     (apply hash-map))))

(defn -main [& args]
  (prn ::server ::listening port)
  (->> port (serve app/main) :chan (async/<!!)))

#_(
   (require 'jaq.http.server.net :reload)
   (in-ns 'jaq.http.server.net)
   (compile 'jaq.http.server.net)
   *e
   *ns*
   (def s (serve app/main 10010))
   s
   (.isClosed s)
   (-> s :server (.close))
   (slurp "http://localhost:10010")
   )
