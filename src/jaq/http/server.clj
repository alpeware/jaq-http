(ns jaq.http.server
  "Functional HTTP server."
  (:gen-class)
  (:require
   [clojure.walk :as walk]
   [jaq.http.server.nio :as nio]
   [jaq.http.xrf.app :as app]
   [jaq.http.xrf.nio :as n]
   [jaq.http.xrf.server :as server]
   [jaq.http.xrf.signaling :as signaling]
   [jaq.http.xrf.repl :as repl]))

(set! *warn-on-reflection* true)

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(defn register! []
  (Thread/setDefaultUncaughtExceptionHandler
   (reify Thread$UncaughtExceptionHandler
     (uncaughtException [_ thread ex]
       (prn ex "Uncaught exception on" (.getName thread))))))

(defn serve [port xrf]
  (nio/serve port xrf))

(def repl-xf
  server/repl-rf
  #_(comp
   (server/server-rf
    server/repl-rf)))

(defn -main [& args]
  (register!)
  (def s
    (->> [{:context/bip-size (* 1 4096)
           :http/port (or
                       (some-> env :PORT (Integer/parseInt))
                       3000)
           :http/host "localhost"
           :http/scheme :http
           :http/minor 1 :http/major 1}]
         (into [] #_repl/repl-rf repl-xf)
         (first)))
  #_(->> (or
        (some-> env :PORT (Integer/parseInt))
        3000)
       (serve app/repl)))

#_(
   *ns*
   (in-ns 'jaq.http.server)
   s
   *e
   (do
     (-> s (first) :async/stop! (apply []))
     (-main))
   )
