(ns jaq.gcp.gmail
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.walk :as walk]
   [clojure.java.io :as io]
   [jaq.gcp.common :as common]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.params :as params]
   #_[jaq.http.xrf.json :as json])
  (:import
   #_[javax.mail.internet MimeMessage MimeMultipart MimeBodyPart InternetAddress]
   #_[javax.mail Session Multipart MessagingException]
   [java.util Base64]
   [java.nio ByteBuffer ByteOrder]))

(def service-name "gmail.googleapis.com")
(def root "gmail.googleapis.com")
(def version "v1")
(def path [:gmail version])

(def rest-service-rf
  (comp
   (fn [rf]
     (fn
       ([] (rf))
       ([acc] (rf acc))
       ([acc {:rest/keys [root-url service-path]
              :or {root-url root service-path path}
              :as x}]
        (->> (assoc x
                    :rest/root-url root-url
                    :rest/service-path service-path)
             (rf acc)))))
   common/rest-rf
   common/auth-rf))

(def profile-rf
  (map (fn [{:gmail/keys [user]
             :or {user :me}
             :as x}]
         (assoc x :rest/path [:users user :profile]))))

;; TODO: paging
(def messages-rf
  (map (fn [{:gmail/keys [user email]
             :http/keys [params headers]
             :or {user :me}
             :as x}]
         (-> x
             (assoc :rest/path [:users user :messages])))))

(def message-rf
  (map (fn [{:gmail/keys [user email]
             {:keys [id] :as params} :http/params
             :or {user :me}
             :as x}]
         (-> x
             (assoc :http/params (-> params (dissoc :id))
                    :rest/path [:users user :messages id])))))

(def raw-rf
  (map (fn [{{:keys [headers body id]} :gmail/email
             :as x}]
         (assoc x :gmail/raw (->> (str
                                   (->> headers
                                        (map (fn [[k v]]
                                               [(-> k (name) (string/capitalize)) v]))
                                        (map (fn [xs]
                                               (string/join ": " xs)))
                                        (string/join "\r\n"))
                                   "\r\n"
                                   "MIME-Version: 1.0\r\n"
                                   "Content-Type: text/html; charset=utf-8\r\n"
                                   "Content-Transfer-Encoding: base64\r\n"
                                   "\r\n"
                                   (->> body (.getBytes) (.encodeToString (Base64/getEncoder))))
                                  (.getBytes)
                                  (.encodeToString (Base64/getUrlEncoder)))))))
#_(

   (require 'hiccup.core)

   (into [] raw-rf [{:gmail/email {:headers {:from "help@frontpageping.com"
                                             :to "alpeware@gmail.com"
                                             :subject "Testing"
                                             :date "Fri, 21 Aug 2020 04:00:00 -0600"}
                                   :body "Hey!"}}])
   *e
   (let [{:keys [headers body]} {:headers {:from "help@frontpageping.com"
                                           :to "alpeware@gmail.com"
                                           :subject "Testing"
                                           :date "Fri, 21 Aug 2020 04:00:00 -0600"}
                                 :body "Hey!"}]
     (str
      (->> headers
           (map (fn [[k v]]
                  [(-> k (name) (string/capitalize)) v]))
           (map (fn [xs]
                  (string/join ": " xs)))
           (string/join "\r\n"))
      "\r\n\r\n"
      body))


   )

(def send-rf
  (map (fn [{:gmail/keys [user email raw]
             :http/keys [params headers]
             :or {user :me}
             :as x}]
         (-> x
             (dissoc :http/params)
             (assoc :http/query-params (-> params (assoc :uploadType :media))
                    :http/headers (assoc headers :content-type :json)
                    :rest/method :POST
                    :http/body (clojure.data.json/write-str {:raw raw})
                    :rest/path [:users user :messages :send])))))

#_(
   (in-ns 'jaq.gcp.gmail)
   (->> [{:gmail/user :me}]
        (into []
              (comp
               raw-rf
               send-rf
               rest-service-rf
               )))

   (->> [{:gmail/user :me}]
        (into []
              (comp
               rest-service-rf
               profile-rf
               )))

   )


#_(

   (def x
     (let [xf (comp
               jaq.http.xrf.nio/selector-rf
               (jaq.http.xrf.nio/thread-rf
                (comp
                 (jaq.http.xrf.nio/select-rf
                  (comp
                   jaq.http.xrf.nio/auth-chan
                   (drop-while (fn [{:oauth2/keys [expires-in]}]
                                 (and (not expires-in)
                                      (> (System/currentTimeMillis) expires-in))))
                   (rf/one-rf :oauth2/access-token (comp
                                                    (map :oauth2/access-token)))
                   (map (fn [x]
                          (-> x
                              (dissoc :http/json :http/body :http/chunks :http/headers :ssl/engine))))
                   #_messages-rf
                   #_message-rf
                   (map (fn [{:gmail/keys [email] :as x}]
                          (prn ::email email)
                          x))
                   raw-rf
                   #_profile-rf
                   send-rf
                   rest-service-rf
                   (map (fn [{:gmail/keys [raw] :as x}]
                          (def y x)
                          (prn ::raw raw)
                          x))
                   (jaq.http.xrf.nio/channel-rf
                    (comp
                     jaq.http.xrf.nio/ssl-connection
                     (jaq.http.xrf.ssl/request-ssl-rf (comp
                                                       jaq.http.xrf.http/http-rf
                                                       #_(map (fn [{:http/keys [req] :as x}]
                                                                (prn ::req req)
                                                                x))))
                     (jaq.http.xrf.ssl/receive-ssl-rf jaq.http.xrf.nio/json-response)
                     jaq.http.xrf.nio/close-connection))
                   (drop-while (fn [{:http/keys [json] :as x}]
                                 (nil? json)))
                   (map (fn [{:context/keys [store]
                              :http/keys [json] :as x}]
                          (vreset! store json)
                          x))))
                 jaq.http.xrf.nio/close-rf)))]
       (->> [{:context/bip-size (* 5 4096)
              :context/store (volatile! nil)
              :oauth2/file ".fpp.edn"
              :oauth2/client-id "806982752248-qti1kst5jkd96nbgmpev8ms7902ejr3v.apps.googleusercontent.com"
              :gmail/email {:headers {:from "help@frontpageping.com"
                                      :to "alpeware@gmail.com"
                                      :bcc "admin@frontpageping.com"
                                      :subject (str "Testing " (rand-int 100))}
                            :body
                            (hiccup.core/html (fpp.pages/verification-email "123456"))
                            #_(hiccup.core/html [:html
                                               [:head
                                                #_[:style {:type "text/css"}
                                                   "@import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700&display=swap')"]
                                                #_[:style fpp.pages/styles]
                                                [:style
                                                 (let [border-thin (str (/ 1 (* 1.4 5)) "rem")
                                                       s3 (str (* 1 1.4 3) "rem")
                                                       color-dark "#050505"
                                                       color-light "#fafafa"]
                                                   (->>
                                                    [
                                                     [:body {:font-family "Barlow Condensed,Helvetica,sans-serif"
                                                             :color color-dark
                                                             :background-color color-light}]
                                                     [:hr {:padding [border-thin 0 0]
                                                           :border-left-width 0
                                                           :border-bottom-width border-thin
                                                           :border-right-width 0
                                                           :border-top-width border-thin}]
                                                     [:.main {:margin-top s3
                                                              :margin-bottom s3
                                                              :margin-left "auto"
                                                              :margin-right "auto"
                                                              :min-width (str (/ 65 1.4 1.4) "ch")
                                                              :max-width (str 65 "ch")}]
                                                     [:.card {:padding "1rem"
                                                              :box-sizing "border-box"
                                                              :margin-left "auto"
                                                              :margin-right "auto"
                                                              :background-color color-dark
                                                              :color color-light
                                                              :height "auto"}]
                                                     [:.text-center {:text-align "center"}]]
                                                    (apply jaq.http.xrf.css/css)))
                                                 ]]
                                               [:body
                                                [:div.main
                                                 fpp.pages/cover
                                                 [:div.stack
                                                  [:h2 "Verification code"]
                                                  [:p
                                                   "Enter the following verification code"]
                                                  [:p
                                                   [:strong "12345"]]]
                                                 [:div.divider]
                                                 [:div fpp.pages/footer]]]])}}]
            (into [] xf)
            (first))))

   *ns*
   ;; TODO: grab all chunks
   (def x *1)
   (->> x :context/store (deref) #_(keys))
   (->> x :nio/selector (.keys))
   (->> x :nio/selector (.close))

   (require 'fpp.pages)
   (require 'garden.core)

   fpp.pages/styles
   (->> x :async/thread (.getState))

   (->> y :gmail/raw (.decode (Base64/getUrlDecoder)) (String.))
   (->> y :gmail/raw)
   (->> y keys)
   (->> y :http/headers)

   (->> {:headers {:from "help@frontpageping.com"
                   :to "alpeware@gmail.com"
                   :subject "Testing"
                   :date "Fri, 21 Aug 2020 04:00:00 -0600"}
         :body "Hey!"}
        :headers
        (map (fn [[k v]]
               [(-> k (name) (string/capitalize)) v]))
        (map (fn [xs]
               (string/join ": " xs)))
        (string/join "\r\n")
        ((fn [s] (str s "\r\n" "\r\n"))))

   ;; email
   (->> x :context/store (deref) :snippet)
   (->> x :context/store (deref) :payload (keys))
   (->> x :context/store (deref) :payload :headers)
   (->> x :context/store (deref) :payload :mimeType)
   (->> x :context/store (deref) :payload :headers)

   (-> x :context/store (deref) :payload (dissoc :body :parts) #_(keys))

   (keys x)

   (in-ns 'jaq.gcp.gmail)
   (require 'jaq.gcp.gmail)

   (in-ns 'clojure.core)
   *e


   )
