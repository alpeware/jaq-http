(ns metosin
  (:require [pohjavirta.server :as server]))

(defn handler [_]
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body "hello"})

(defn -main [& args]
  (-> handler
      (server/create {:port 3000
                      :host "0.0.0.0"})
      (server/start)))
