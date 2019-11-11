(ns jaq.http.xrf.response
  (:import
   [java.nio.charset StandardCharsets Charset]
   [java.nio ByteBuffer CharBuffer]))

(def ^Charset charset StandardCharsets/UTF_8)

;;TODO: properly handle status and headers
(def plain
  (map (fn [{:keys [status headers body] :as x}]
         (let [^String res
               (->> ["HTTP/1.1" " " status " " "OK" "\r\n"
                     ;;"Host: " (:host headers) "\r\n"
                     ;;"Date: Sat, 02 Nov 2019 21:16:00 GMT" "\r\n"
                     "Content-type: text/plain" "\r\n"
                     "Connection: close" "\r\n"
                     "Content-length: " (count body) "\r\n"
                     "\r\n"
                     body]
                    (apply str))]
           (-> res
               (.getBytes charset)
               (ByteBuffer/wrap))))))

#_(
   *ns*
   (in-ns 'jaq.http.xrf.response)

   (sequence
    (comp
     (map (fn [e] e))
     plain)
    [{:status 200 :headers {} :body "foo"}])
   )
