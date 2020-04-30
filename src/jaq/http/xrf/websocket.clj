(ns jaq.http.xrf.websocket
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as j]
   [garden.core :refer [css]]
   [hiccup.core :refer [html]]
   [hiccup.page :as page]
   [jaq.http.xrf.header :as header]
   [jaq.http.xrf.http :as http]
   [jaq.http.xrf.json :as json]
   [jaq.http.xrf.params :as params]
   [jaq.http.xrf.ssl :as ssl]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]
   [jaq.repl :as r]
   [net.cgrand.xforms :as x])
  (:import
   [java.nio.charset Charset]
   [java.nio ByteBuffer]
   [java.security MessageDigest]
   [java.util Base64]))

(def ^Charset utf8
  "Default Charset for decoding."
  (Charset/forName "UTF-8"))

(def ^MessageDigest sha1 (MessageDigest/getInstance "SHA-1"))

(def ^Base64 encoder (Base64/getEncoder))

(def magic-id "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defn encrypt [^MessageDigest digest s]
  (.reset digest)
  (-> s (.getBytes utf8) (->> (.update digest)))
  (.digest digest))

(defn base64 [^Base64 encoder b]
  (.encodeToString encoder b))

(defn handshake [key]
  (->> (str key magic-id)
       (encrypt sha1)
       (base64 encoder)))

(def op-codes
  {0x0 :cont 0x1 :text 0x2 :binary
   0x8 :close 0x9 :ping 0xa :pong})

(def op-map
  (->> op-codes
       (map (fn [[k v]] [v k]))
       (into {})))

#_(
   (in-ns 'jaq.http.xrf.websocket)


   ;; example from https://en.wikipedia.org/wiki/WebSocket#Protocol_handshake
   (= "HSmrc0sMlYUkAGmm5OPpG2HaGWk="
      (handshake "x3JJHMbDL1EzLkh9GBhXDw=="))


   ;; example from https://www.websocket.org/echo.html
   (= "nyPt0e3FZpKhRefOxHcVMozaFKk="
      (handshake "MiQfAJG5SQweHoApl6L4cw=="))

   (->>"FOO BAR"
       (encrypt sha1)
       (base64 encoder))

   )

(def decode-frame-rf
  (fn [rf]
    (let [final (volatile! nil)
          op (volatile! nil)
          masked (volatile! nil)
          len (volatile! nil)
          masking-key (volatile! nil)
          vacc (volatile! [])
          payload (volatile! nil)
          ;; TODO: need to reset for each frame
          assoc-fn (fn [acc x]
                     (let [frame {:final @final
                                  :op (get op-codes @op :reserved)
                                  :masked @masked
                                  :len @len
                                  :payload @payload}
                           frame (if @masked
                                   (assoc frame :masking-key @masking-key)
                                   frame)]
                       (vreset! final nil)
                       (vreset! op nil)
                       (vreset! masked nil)
                       (vreset! len nil)
                       (vreset! masking-key nil)
                       (vreset! vacc [])
                       (vreset! payload nil)
                       (->> (assoc x
                                   :ws/frame frame)
                            (rf acc))))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:keys [byte] :as x}]
         #_(prn ::byte byte ::final @final ::op @op ::masked @masked ::masking-key @masking-key ::len @len)
         (cond
           ;; first byte
           (and
            (nil? @final)
            (nil? @op))
           (do
             (->> (bit-test byte 0)
                  (vreset! final))
             (->> (bit-and byte 0x0F)
                  (vreset! op))
             acc)
           ;; second byte
           (and
            (nil? @masked)
            (not @len))
           (do
             (->> (bit-test byte 7)
                  (vreset! masked))
             (->> (bit-and byte 0x7F)
                  (vreset! len))
             acc)
           ;; extended payload length
           ;; 16-bit unsigned integer
           (and
            (= @len 126)
            (< (count @vacc) 2))
           (do
             (vswap! vacc conj byte)
             (when (= 2 (count @vacc))
               (-> @vacc
                   (byte-array)
                   (ByteBuffer/wrap)
                   (.getShort)
                   (bit-and 0xFFFF)
                   (->> (vreset! len)))
               (vreset! vacc []))
             acc)

           ;; 64-bit unsigned integer
           (and
            (= @len 127)
            (< (count @vacc) 8))
           (do
             (vswap! vacc conj byte)
             (when (= 8 (count @vacc))
               (-> @vacc
                   (byte-array)
                   (ByteBuffer/wrap)
                   (.getLong)
                   (->> (vreset! len)))
               (vreset! vacc []))
             acc)

           ;; masking key
           (and
            @masked
            (not @masking-key)
            (< (count @vacc) 4))
           (do
             (vswap! vacc conj byte)
             (when (= 4 (count @vacc))
               (vreset! masking-key @vacc)
               (vreset! vacc []))
             acc)

           ;; payload
           (= @len 0)
           (assoc-fn acc x)

           (and
            @masked
            (< (count @vacc) @len))
           (do
             (->>
              (mod (count @vacc) 4)
              (get @masking-key)
              (bit-xor byte)
              (vswap! vacc conj))
             (if (= (count @vacc) @len)
               (do
                 (vreset! payload @vacc)
                 (vreset! vacc [])
                 (assoc-fn acc x))
               acc))

           (and
            (not @masked)
            (< (count @vacc) @len))
           (do
             (vswap! vacc conj byte)
             (if (= (count @vacc) @len)
               (do
                 (vreset! payload @vacc)
                 (vreset! vacc [])
                 (assoc-fn acc x))
               acc))

           :else
           acc))))))

#_(
   (in-ns 'jaq.http.xrf.websocket)
   *e

   (-> jaq.http.xrf.nio/x :context/ws (deref) (last) :payload count)


   (let [byte -122]
     [(bit-test byte 0)
      (bit-and byte 0x7F)])

   (Integer/toBinaryString 0x80)
   (bit-test 0x80 7)

   (.rewind bs)
   (into [] (comp
             (map (fn [x]
                    {:byte x}))
             frame-rf
             #_(take 2)
             #_(map :ws/frame)
             #_(map :payload)
             #_(map (fn [x]
                      (->> x (map char)))))
         (rest @bb))

   (-> (bit-xor 20 117) char)

   (-> *1 first (.get))



   (->> (byte-array [1 2])
        (ByteBuffer/wrap)
        (.getShort))

   (->> (byte-array [71 69])
        (ByteBuffer/wrap)
        (.decode utf8)
        (.toString))
   )



(def decode-message-rf
  (fn [rf]
    (let [frames (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {{:keys [final op payload] :as frame} :ws/frame
               :as x}]
         (cond
           (and
            (not final))
           (do
             (vswap! frames conj frame)
             acc)

           (and
            final
            (= op :text))
           (->> (assoc x
                       :ws/op op
                       :ws/message (->> (byte-array payload)
                                        (ByteBuffer/wrap)
                                        (.decode utf8)
                                        (.toString)))
                (rf acc))

           (and
            final
            (= op :binary))
           (->> (assoc x
                       :ws/op op
                       :ws/message (->> (byte-array payload)
                                        (ByteBuffer/wrap)))
                (rf acc))

           (and
            final
            (contains? #{:ping :pong :close} op))
           (->> (assoc x
                       :ws/op op
                       :ws/message (->> (byte-array payload)
                                        (ByteBuffer/wrap)))
                (rf acc))

           ;; continuation text
           (and
            final
            (= op :cont)
            (->> @frames (first) :ws/frame :op (= :text)))
           (let [f @frames
                 op (->> @frames (first) :ws/frame :op)
                 message (->> @frames
                              (map :ws/frame)
                              (mapcat :payload)
                              (apply (fn [& xs]
                                       (->> (byte-array xs)
                                            (ByteBuffer/wrap)
                                            (.decode utf8)
                                            (.toString)))))]
             (prn ::frames (count @frames))
             (vreset! frames nil)
             (->> (assoc x
                         :ws/op op
                         :ws/frames f
                         :ws/message message)
                  (rf acc)))

           ;; continuation binary
           (and
            final
            (= op :cont)
            (->> @frames (first) :ws/frame :op (= :binary)))
           (let [op (->> @frames (first) :ws/frame :op)
                 message (->> @frames
                              (map :ws/frame)
                              (mapcat :payload)
                              (apply (fn [& xs]
                                       (->> (byte-array xs)
                                            (ByteBuffer/wrap)))))]
             (vreset! frames nil)
             (->> (assoc x
                         :ws/op op
                         :ws/message message)
                  (rf acc)))

           :else
           acc))))))

#_(

   (int true)
   (let [final true op 1 len 1200000
         frame (ByteBuffer/allocateDirect 10)]
     (.rewind frame)
     ;; first byte
     (.put frame (unchecked-byte
                  (if final
                    (-> (get op-map op 1)
                        (bit-set 7))
                    (get op-map op 1))))
     ;; len
     (cond
       (<= len 125) (.put frame (unchecked-byte len))
       (<= len 0xFFFF) (do
                         (.put frame (unchecked-byte 126))
                         (.putShort frame (short len)))
       :else (do
               (.put frame (unchecked-byte 127))
               (.putLong frame (long len))))
     (.flip frame)
     )



   )

;; returns a bytebuffer and can be used w/ send-rf
;; TODO: support masking
(def encode-frame-rf
  (fn [rf]
    (let [frame (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {{:keys [final op masked len payload masking-key]} :ws/frame
               :as x}]
         (when-not @frame
           (vreset! frame (ByteBuffer/allocateDirect 10)))
         (.rewind @frame)
         ;; first byte
         (.put @frame (unchecked-byte
                       (if final
                         (-> (get op-map op 1)
                             (bit-set 7))
                         (get op-map op 1))))
         ;; len
         (cond
           (<= len 125) (.put @frame (unchecked-byte len))
           (<= len 0xFFFF) (do
                             (.put @frame (unchecked-byte 126))
                             (.putShort @frame len)) ;; (short 33611)
           :else (do
                   (.put @frame (unchecked-byte 127))
                   (.putLong @frame (long len))))
         (.flip @frame)
         (->> (assoc x :http/req [@frame payload])
              (rf acc)))))))

;; TODO: fragmented messages
(def encode-message-rf
  (fn [rf]
    (let [frame (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:ws/keys [message op]
               :as x}]
         (->> (assoc x :ws/frame {:final true :op op
                                  :len (if (= op :text)
                                         (count message) (.limit message))
                                  :payload message})
              (rf acc)))))))

#_(
   (into [] (comp
             encode-message-rf
             encode-frame-rf)
         [{:ws/message "foo bar" :ws/op :text}
          #_{:ws/frame {:final true :op :text :len 1 :payload "a"}}])
   )

#_(
   (in-ns 'jaq.http.xrf.websocket)

   (into [] (comp
             (map (fn [x]
                    {:byte x}))
             frame-rf
             message-rf
             #_(drop 3)
             #_(map :ws/message))
         (rest @bb))

   (->> [{:foo [97]} {:foo [101]} {:foo [88 74]}]
        (mapcat :foo)
        (apply (fn [& xs]
                 (->> (byte-array xs)
                      (ByteBuffer/wrap)
                      (.decode utf8)
                      (.toString)))))

   *e
   (let [n (dec (count @bb))
         b (ByteBuffer/allocate n)]
     (->> (rest @bb)
          (map (fn [x]
                 (.put b x)))
          (doall))
     (def bs b))

   (.flip bs)
   (unchecked-byte (.get bs))
   (.rewind bs)
   (decode bs)

   (let [_ (.rewind bs)
         b (bit-and 0xff (.get bs))]
     (bit-and b 0x80)
     )

   (.rewind bb)
   (.get bb)
   2r1000111

   (Integer/toString 2r1110 16)

   (Integer/toBinaryString 71)
   (Integer/toBinaryString -127)

   (bit-and 0xff -127)
   (bit-and 0xff 129)

   (Integer/toBinaryString 0x80)
   (Integer/toBinaryString 0x0F)

   (Integer/toBinaryString (bit-and 129 0x80))
   (Integer/toBinaryString (bit-and 129 0x0F))

   bb
   (.rewind bb)
   @bb
   (def bb (-> jaq.http.xrf.nio/x :context/ws)))

#_(
   (in-ns 'jaq.http.xrf.websocket)


   ;; example from https://en.wikipedia.org/wiki/WebSocket#Protocol_handshake
   (= "HSmrc0sMlYUkAGmm5OPpG2HaGWk="
      (handshake "x3JJHMbDL1EzLkh9GBhXDw=="))


   ;; example from https://www.websocket.org/echo.html
   (= "nyPt0e3FZpKhRefOxHcVMozaFKk="
      (hash "MiQfAJG5SQweHoApl6L4cw=="))

   (->>"FOO BAR"
       (encrypt sha1)
       (base64 encoder))

   )
