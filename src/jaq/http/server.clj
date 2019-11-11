(ns jaq.http.server
  "Functional HTTP server."
  (:gen-class)
  (:require
   [clojure.walk :as walk]
   [jaq.http.server.nio :as nio]
   [jaq.http.xrf.app :as app]))

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

(defn -main [& args]
  (register!)
  (->> (or
        (some-> env :PORT (Integer/parseInt))
        3000)
       (serve app/repl)
       :future
       (deref)))


#_(
   *ns*
   (in-ns 'jaq.http.server)
   jaq.http.server.nio/*http-server*
   *e
   )
