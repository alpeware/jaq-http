(ns aleph
  (:require [aleph.http :as http]))

(defn handler [req]
  {:status 200
   :headers {"content-type" "text/plain"}
   :body "hello!"})

(defn -main [& args]
  (http/start-server handler {:port 3000}))
