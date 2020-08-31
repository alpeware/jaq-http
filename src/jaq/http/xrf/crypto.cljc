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

;; clj

#?(:clj
   (def public-key-rf
     (comp
      (map (fn [{{:crypto/keys [data jwk signature]} :datachannel/payload
                 :as x}]
             (let [{:keys [alg kty n e]} jwk
                   decoder (-> (Base64/getUrlDecoder))
                   kf (KeyFactory/getInstance kty)
                   modulus (->> n (.decode decoder) (BigInteger. 1))
                   exponent (->> e (.decode decoder) (BigInteger. 1))
                   public-key (->> (RSAPublicKeySpec. modulus exponent)
                                   (.generatePublic kf))]
               (assoc x :peer/public-key public-key)))))))

#?(:clj
   (def verify-rf
     (comp
      (map (fn [{{:crypto/keys [data jwk signature]} :datachannel/payload
                 :peer/keys [public-key]
                 :as x}]
             (let [sig (Signature/getInstance "SHA256withRSA")]
               (.initVerify sig public-key)
               (.update sig data)
               (assoc x :crypto/verified (.verify sig signature))))))))

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
         s "foo@bar.com"]
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
