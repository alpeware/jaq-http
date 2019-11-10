(ns jaq.http.server.net
  (:gen-class)
  (:require
   [clojure.core.async :as async]
   [clojure.string :as string]
   [clojure.java.io :as io]
   [clojure.walk :as walk]
   [jaq.http.xrf.app :as app])
  (:import
   [java.io BufferedReader BufferedWriter IOException]
   [java.net Socket ServerSocket SocketException]
   [java.nio.charset StandardCharsets Charset]
   [java.time.format DateTimeFormatter]
   [java.time ZonedDateTime ZoneId]))

(set! *warn-on-reflection* true)

(def ^:dynamic *http-server* nil)

(def ^:dynamic *app-xrf* nil)

(def ^:dynamic *chan-buf* 1)

(def buffer-size (* 256 1024))

(def charset StandardCharsets/UTF_8)

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(def ^DateTimeFormatter pattern
  (DateTimeFormatter/ofPattern "EEE, dd MMM yyyy HH:mm:ss zzz"))

(def ^ZoneId zone (ZoneId/of "GMT"))

(defn ^String now []
  (-> zone
      (ZonedDateTime/now)
      (.format pattern)))

(def port (or (some-> env :PORT (Integer/parseInt))
              3000))

(defn response [{:keys [status headers body]}]
  (->> ["HTTP/1.1" " " status " " "OK" "\r\n"
        ;;"Date:" " " (now) "\r\n"
        ;;"Host:" " " (:host headers) "\r\n"
        ;;"Server:" " alpeware/jaq" "\r\n"
        "Content-Type: text/plain" "\r\n"
        "Connection: close" "\r\n"
        "Content-Length: " (count body) "\r\n"
        "\r\n"
        body]
       (apply str)))

(defn exchange [^Socket client]
  (let [ch (async/chan *chan-buf* *app-xrf* (fn [e] (prn ::exception e) {:exception e}))]

    ;; req
    (async/thread
      (try
        (with-open [^BufferedReader in (io/reader (.getInputStream client))]
          (loop []
            (let [c (.read in)]
              (when (> c 0)
                (async/>!! ch (char c))
                (recur)))))
        (catch SocketException _)))

    ;; res
    (async/thread
      (try
        (with-open [^BufferedWriter out (io/writer (.getOutputStream client))]
          (some->> (async/<!! ch)
               (response)
               (char-array)
               (.write out))
          (.flush out))
        (catch SocketException _))
      (async/close! ch)
      (.close client))))

(defn serve [xrf p]
  (let [^ServerSocket server (ServerSocket. p)
        shutdown (async/chan)
        shutdown-mult (async/mult shutdown)
        main-shutdown (async/chan)]
    (prn ::starting ::port p)
    ;; app
    (alter-var-root #'*app-xrf* (constantly xrf))
    (async/tap shutdown-mult main-shutdown)

    (async/thread
      (loop []
        (if (async/poll! main-shutdown)
          (try
            (prn ::shutdown)
            (.close server)
            (catch IOException _))
          (when-let [^Socket client (.accept server)]
            #_(prn ::clients @clients)
            (exchange client)
            (recur)))))

    (alter-var-root
     #'*http-server*
     (constantly {:xrf xrf
                  :server server
                  :shutdown shutdown}))))

(defn -main [& args]
  (->> port (serve app/repl) :shutdown (async/<!!)))

#_(
   (require 'jaq.http.server.net :reload)
   (in-ns 'jaq.http.server.net)
   (compile 'jaq.http.server.net)
   *e
   @clients
   *ns*
   (def s (serve app/repl 10010))
   s

   (-> s :server (.close))
   (slurp "http://localhost:10010")
   (in-ns 'clojure.core)
   )
