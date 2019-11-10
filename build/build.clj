(ns build)

(defn build []
  (with-bindings
    {#'*compiler-options* {:direct-linking true :elide-meta [:doc :file :line :added]}
     #'clojure.spec.alpha/*compile-asserts* false}
    (compile 'jaq.http.server)))

(defn -main [& args]
  (build))
