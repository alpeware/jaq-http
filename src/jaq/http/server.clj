(ns jaq.http.server
  "Functional HTTP server."
  (:gen-class)
  (:require
   [clojure.core.async :as async]
   [clojure.walk :as walk]
   [jaq.http.server.nio :as nio]
   [jaq.http.xrf.app :as app]))

(def env
  (->> (System/getenv)
       (into {})
       (walk/keywordize-keys)))

(defn serve [port xrf]
  (nio/serve port xrf))

(defn -main [& args]
  (System/setProperty "clojure.core.async.pool-size" "16")
  (->> (or
        (some-> env :PORT (Integer/parseInt))
        3000)
       (serve app/repl)
       :shutdown
       (async/<!!)))

#_(
   *ns*
   (in-ns 'jaq.http.server)
   jaq.http.server.nio/*http-server*
   *e
   )
