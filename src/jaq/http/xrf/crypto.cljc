(ns jaq.http.xrf.crypto
  #?(:cljs
     (:require [clojure.string :as string]
               [clojure.walk :as walk]
               [jaq.http.xrf.rf :as rf])
     :clj
     (:require [clojure.data.json :as json]
               [clojure.string :as string]
               [jaq.http.xrf.rf :as rf]))
  #?(:cljs
     (:import [goog.events EventTarget EventType])
     :clj
     (:import
      [java.nio ByteBuffer]
      [java.security.spec RSAPublicKeySpec]
      [java.security KeyFactory PublicKey Signature SecureRandom MessageDigest]
      [java.util UUID Base64])))

#_(
   (require 'jaq.http.xrf.crypto :reload)
   (in-ns 'jaq.http.xrf.crypto)
   )
;; cljs
;; certificate
#?(:cljs
   (def generate-certificate-rf
     (comp
      (rf/await-rf :rtc/certificate
                   (fn [{:crypto/keys [algorithm] :as x}]
                     (js/RTCPeerConnection.generateCertificate
                      (clj->js algorithm)))))))

#_(

   (into []
         (comp
          (map (fn [{:crypto/keys [algorithm extractable usages] :as x}]
                 x))
          generate-certificate-rf
          (map (fn [x]
                 (prn x)
                 (def y x)
                 x))
          (remove (constantly true)))
         [{:crypto/algorithm {:name "RSASSA-PKCS1-v1_5"
                              :hash "SHA-256"
                              :modulusLength 2048
                              :publicExponent (js/Uint8Array. [1, 0, 1])}}])

   (->> y :rtc/certificate (.-__proto__) (.getOwnPropertyNames js/Object))
   (-> y :rtc/certificate (.-expires) (- (.now js/Date)) (/ (* 1000 60 60 24)))
   (-> y :rtc/certificate (.getFingerprints))

   (-> {:name "RSASSA-PKCS1-v1_5"
        :hash "SHA-256"
        :modulusLength 2048
        :publicExponent (js/Uint8Array. [1, 0, 1])}
       (clj->js)
       (js/RTCPeerConnection.generateCertificate)
       (.then (fn [e] (.info js/console e) e))
       (.then (fn [e] (-> (.-expires e)
                          (- (js/Date.now))
                          (/ (* 1000 60 60 24))
                          (prn)))))
   )

;; crypto
#?(:cljs
   (def generate-keys-rf
     (comp
      (rf/await-rf :crypto/keys
                   (fn [{:crypto/keys [algorithm extractable usages] :as x}]
                     (js/window.crypto.subtle.generateKey
                      (clj->js algorithm)
                      extractable
                      (clj->js usages)))))))

#?(:cljs
   (def sign-rf
     (comp
      (rf/await-rf :crypto/signature
                   (fn [{:crypto/keys [algorithm data]
                         crypto-keys :crypto/keys
                         :as x}]
                     (js/window.crypto.subtle.sign
                      (-> algorithm (select-keys [:name]) (clj->js))
                      (-> crypto-keys (.-privateKey))
                      data))))))

#?(:cljs
   (def export-rf
     (comp
      (rf/await-rf :crypto/jwk
                   (fn [{:crypto/keys [algorithm]
                         crypto-keys :crypto/keys
                         :as x}]
                     (js/window.crypto.subtle.exportKey
                      "jwk"
                      (-> crypto-keys (.-publicKey)))))
      (map (fn [{:crypto/keys [jwk] :as x}]
             (assoc x
                    :crypto/jwk (->> jwk (js->clj) (walk/keywordize-keys))))))))
#_(

   (into []
         (comp
          (map (fn [{:crypto/keys [algorithm extractable usages] :as x}]
                 x))
          generate-keys-rf
          (map (fn [x]
                 (assoc x :crypto/data (js/ArrayBuffer. 10))))
          sign-rf
          export-rf
          (map (fn [x]
                 (prn x)
                 (def y x)
                 x))
          (remove (constantly true)))
         [{:crypto/algorithm {:name "RSASSA-PKCS1-v1_5"
                              :hash "SHA-256"
                              :modulusLength 2048
                              :publicExponent (js/Uint8Array. [1, 0, 1])}
           :crypto/extractable false
           :crypto/usages ["verify" "sign"]}])

   (-> z :crypto/keys (.-publicKey))
   (->> z (.-publicKey) (js/window.crypto.subtle.exportKey #_"spki" "jwk"))

   (-> y :crypto/signature (.-byteLength))

   (-> y :crypto/keys (.-publicKey))
   (-> y :crypto/jwk)
   (-> y :crypto/signature (js/Uint8Array.) (js/Array.from))

   (let [buf (-> y :crypto/signature)]
     (doseq [i (range (.-byteLength buf))
             byte ()]))

   (-> (js/ArrayBuffer. 10) (.-byteLength))

   )

#?(:cljs
   (def sha256-rf
     (comp
      (rf/await-rf :crypto/hash
                   (fn [{:crypto/keys [s data] :as x}]
                     (let [data (if s
                                  (->> s (str) (.encode (js/TextEncoder.)))
                                  data)]
                       (->> data
                            (js/window.crypto.subtle.digest "SHA-256")))))
      (rf/one-rf :crypto/sha256
                 (map (fn [{:crypto/keys [hash] :as x}]
                        (->> hash
                             (js/Uint8Array.)
                             (.from js/Array)
                             (map (fn [e]
                                    (-> e
                                        (.toString 16)
                                        (string/upper-case)
                                        (.padStart 2 "0"))))
                             (into []))))))))

#_(
   (->> "foo" (.encode (js/TextEncoder.)) (js/window.crypto.subtle.digest "SHA-256"))

   (into [] (comp
             sha256-rf
             (map (fn [{:crypto/keys [sha256] :as x}]
                    (assoc x :crypto/sha256 (->> sha256 (string/join "-")))))
             (map (fn [{:crypto/keys [sha256] :as x}]
                    (prn sha256)
                    x))
             (drop-while (fn [_] true)))
         [{:crypto/s "foobar"}])

   (into [] (comp
             sha256-rf
             (map (fn [{:crypto/keys [sha256] :as x}]
                    (assoc x :crypto/sha256 (->> sha256 (string/join "-")))))
             (map (fn [{:crypto/keys [sha256] :as x}]
                    (prn sha256)
                    x))
             (drop-while (fn [_] true)))
         [{:crypto/data (->> "foobar" (.encode (js/TextEncoder.)))}])

   )

;; clj

#?(:clj
   (def public-key-rf
     (comp
      (map (fn [{:crypto/keys [data jwk signature]
                 :as x}]
             #_(def y x)
             #_(
                (->> y :crypto/jwk)
                (let [{:crypto/keys [data jwk signature]
                       :as x} y
                      {:keys [alg kty n e]} jwk
                      decoder (-> (Base64/getUrlDecoder))
                      kf (KeyFactory/getInstance kty)
                      modulus (->> n (.decode decoder) (BigInteger. 1))
                      exponent (->> e (.decode decoder) (BigInteger. 1))
                      public-key (->> (RSAPublicKeySpec. modulus exponent)
                                      (.generatePublic kf))]
                  (assoc x :crypto/public-key public-key))
                )
             (let [{:keys [alg kty n e]} jwk
                   decoder (-> (Base64/getUrlDecoder))
                   kf (KeyFactory/getInstance kty)
                   modulus (->> n (.decode decoder) (BigInteger. 1))
                   exponent (->> e (.decode decoder) (BigInteger. 1))
                   public-key (->> (RSAPublicKeySpec. modulus exponent)
                                   (.generatePublic kf))]
               (assoc x :crypto/public-key public-key)))))))

#?(:clj
   (def verify-rf
     (comp
      (map (fn [{:crypto/keys [data jwk signature public-key]
                 :as x}]
             (let [sig (Signature/getInstance "SHA256withRSA")]
               (.initVerify sig public-key)
               (.update sig data)
               (assoc x :crypto/verified (.verify sig signature))))))))

#_(
   (in-ns 'jaq.http.xrf.crypto)
   (let [{:crypto/keys [data jwk signature public-key]
          :as x} fpp.xfrs.session/y
         x (assoc fpp.xfrs.session/y
                  :crypto/public-key public-key
                  :crypto/data data
                  :crypto/jwk jwk
                  :crypto/signature signature)]
     (let [sig (Signature/getInstance "SHA256withRSA")]
       public-key
       #_(.initVerify sig public-key)
       #_(.update sig data)
       #_(assoc x :crypto/verified (.verify sig signature)))
     )

   (->> fpp.xfrs.session/y :session/public-key)

   (into [] (comp
             (map (fn [{{:session/keys [data signature public-key]
                         :device/keys [jwk]} :datachannel/payload
                        :session/keys [public-key]
                        :as x}]
                    (assoc x
                           :crypto/public-key public-key
                           :crypto/data data
                           :crypto/jwk jwk
                           :crypto/signature signature)))
             verify-rf) [fpp.xfrs.session/y])
   *e
   )

#?(:clj
   (def ^SecureRandom secure-random (SecureRandom.)))

#?(:clj
   (defn random-int
     "Returns a secure random integer between 0 (inclusive) and n (exclusive)."
     [n]
     (-> secure-random
         (.nextDouble)
         (* n)
         (int))))

#?(:clj
   (def random-rf
     (comp
      (map (fn [{:crypto/keys [n] :as x}]
             (assoc x
                    :crypto/random
                    (->> (fn [] (random-int n))
                         (repeatedly)
                         (take n)
                         (into []))))))))

#_(
   (into [] random-rf [{:crypto/n 6}])
   secure-random
   (random-int 1000000)
   (->> (range 2)
        (reduce (fn [acc _] (* acc 10)) 1)
        (random-int)
        (str))

   *e

   )

#?(:clj
   (defn sha1 [s]
     (let [md (MessageDigest/getInstance "SHA-1")]
       (->> s
            (.getBytes)
            (.update md))
       (->> (.digest md)
            (map byte)
            (map (fn [x] (bit-and x 0xff)))
            (map (fn [x] (Integer/toHexString x)))
            (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
            (map (fn [x] (string/upper-case x)))
            (into [])))))

#?(:clj
   (def sha1-rf
     (comp
      (map (fn [{:crypto/keys [s] :as x}]
             (assoc x :crypto/sha1 (sha1 s)))))))

#?(:clj
   (defn sha256 [s]
     (let [md (MessageDigest/getInstance "SHA-256")]
       (->> s
            (.getBytes)
            (.update md))
       (->> (.digest md)
            (map byte)
            (map (fn [x] (bit-and x 0xff)))
            (map (fn [x] (Integer/toHexString x)))
            (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
            (map (fn [x] (string/upper-case x)))
            (into [])))))

#?(:clj
   (def sha256-rf
     (comp
      (map (fn [{:crypto/keys [s] :as x}]
             (assoc x :crypto/sha256 (sha256 s)))))))

#_(
   (in-ns 'jaq.http.xrf.crypto)

   (let [md (MessageDigest/getInstance "SHA-256")
         ;;s "foo@bar.com"
         s "sXsqJFPooh4mARf2EPulHsWrejYz65po50khKjydHw5-e7XcjyAHryHWcXRWIi-ktIjri_VUXFRpgJnOvMHDrI1PuVh-qBPYaSvqU8co2nKid48v82u411lmLKlSMn5oRV7rS4B9kH2z2oxe8Tit8md3gxMLf6s2CKEMkqwYHdeO8BSEF5qUUx_MCPP7AgJonRucxYgVQh0E7kYzR3WXLrhat6LidoJzU74ZbUMHg9YXl1FnojMURHaRl4fear8H_ftJUsSpWOQTK9hyNDv7bmduWa-CdyD5AhDqYhYvyD-ucJfC36liaxkhgT4ZizIxLSDmFy2fN25_gksrPlgJbQ"
         ]
     (->> s
          (.getBytes)
          (.update md))
     (->> (.digest md)
          (map byte)
          (map (fn [x] (bit-and x 0xff)))
          (map (fn [x] (Integer/toHexString x)))
          (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
          (map (fn [x] (string/upper-case x)))
          (into [])))

   )
