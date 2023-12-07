(ns jaq.http.xrf.dtls
  "DTLS over UDP implementation.

  Helpful resources:
  - https://docs.oracle.com/javase/9/security/java-secure-socket-extension-jsse-reference-guide.htm"
  (:require
   [clojure.string :as string]
   [clojure.set :as set]
   [jaq.http.xrf.nio :as nio]
   [jaq.http.xrf.rf :as rf]
   [jaq.http.xrf.params :as params])
  (:import
   [java.math BigInteger]
   [java.io ByteArrayInputStream FileOutputStream FileInputStream
    ObjectOutputStream ObjectInputStream IOException]
   [java.nio.channels
    CancelledKeyException ClosedChannelException
    ServerSocketChannel Selector SelectionKey SocketChannel SelectableChannel]
   [java.nio ByteBuffer CharBuffer]
   [java.security.cert X509Certificate]
   [java.security PrivateKey SecureRandom KeyStore MessageDigest]
   [java.util.concurrent ConcurrentLinkedDeque]
   [java.util Date Base64]
   [javax.net.ssl
    SNIHostName SNIServerName
    SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status
    SSLContext SSLSession SSLException TrustManagerFactory KeyManagerFactory
    X509TrustManager TrustManager X509KeyManager X509ExtendedKeyManager]
   [sun.security.provider X509Factory]
   [sun.security.x509 AlgorithmId X509CertInfo X509CertImpl X500Name CertificateValidity]
   [sun.security.tools.keytool CertAndKeyGen]))

(def default-dn "cn=jaq, o=alpeware, c=US")
(def default-days 10)
(def default-validity (* default-days 86400000))
(def default-key-type "RSA")
(def default-sig-alg "SHA256withRSA")
(def default-key-bits 2048)
(def default-keystore-type "PKCS12")

;; https://stackoverflow.com/a/1271148/7947020
(defn fingerprint [cert]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (->> cert
         (.getEncoded)
         (.update md))
    (->> (.digest md)
         (map byte)
         (map (fn [x] (bit-and x 0xff)))
         (map (fn [x] (Integer/toHexString x)))
         (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
         (map (fn [x] (string/upper-case x)))
         (into []))))

(defn self-cert [& {:cert/keys [alias dn validity key-type sig-alg key-bits]
                  :or {dn default-dn validity default-validity
                       key-type default-key-type sig-alg default-sig-alg
                       key-bits default-key-bits}}]
  (let [x500name (X500Name. dn)
        keytool (CertAndKeyGen. key-type sig-alg)]
    (.generate keytool key-bits)
    (let [cert (.getSelfCertificate keytool x500name validity)]
      {:cert/cert cert
       :cert/fingerprint (fingerprint cert)
       :cert/alias (or alias (str (.getSerialNumber cert)))
       :cert/private-key (.getPrivateKey keytool)})))

#_(

   (self-cert :cert/alias "server")
   )

(defn serialize [filename cert]
  (with-open [fos (FileOutputStream. filename)]
    (let [oos (ObjectOutputStream. fos)]
      (->> cert
           (.writeObject oos)))))

(defn deserialize [filename]
  (with-open [fis (FileInputStream. filename)]
    (let [ois (ObjectInputStream. fis)]
      (-> ^PersistentArrayMap (.readObject ois)))))

#_(
   ;; serialize cert
   (with-open [fos (FileOutputStream. ".certmap.bin")]
     (let [oos (ObjectOutputStream. fos)]
       (->> cert
            ;;:cert/cert
            (.writeObject oos))))

   (with-open [fis (FileInputStream. ".certmap.bin")]
     (let [ois (ObjectInputStream. fis)]
       (-> ^PersistentArrayMap (.readObject ois))))

   (type {})

   )

#_(
   (in-ns 'jaq.http.xrf.dtls)
   (def cert (self-cert :cert/alias "foo"))
   (->> cert
        :cert/cert
        (.getEncoded)
        (map byte)
        (map (fn [x] (bit-and x 0xff)))
        (map (fn [x] (Integer/toHexString x)))
        (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
        (map (fn [x] (string/upper-case x)))
        (into []))

   (let [md (MessageDigest/getInstance "SHA-256")]
     (->> cert
         :cert/cert
         (.getEncoded)
         (.update md))
     (->> (.digest md)
          (map byte)
          (map (fn [x] (bit-and x 0xff)))
          (map (fn [x] (Integer/toHexString x)))
          (map (fn [x] (if (< (count x) 2) (str "0" x) x)))
          (map (fn [x] (string/upper-case x)))
          (into [])))

   (self-cert :cert/alias "foo")
   (self-cert)
   ;; http://cr.openjdk.java.net/~asmotrak/8159416/webrev.08/test/javax/net/ssl/DTLS/DTLSOverDatagram.java.html
   (let [cert (self-cert)
         alias (str (.getSerialNumber cert))
         ks (KeyStore/getInstance default-keystore-type)
         kmf (KeyManagerFactory/getInstance "SunX509")
         tmf (TrustManagerFactory/getInstance "SunX509")
         ctx (SSLContext/getInstance "DTLS")]
     (.load ks nil nil)
     (.setCertificateEntry ks alias cert)
     (.init kmf ks nil)
     (.init tmf ks)
     (.init ctx (.getKeyManagers kmf) (.getTrustManagers tmf) nil)
     (enumeration-seq (.aliases ks)))

   (let [encoder (Base64/getMimeEncoder 64 (.getBytes "\r\n"))
         encoded (str #_(X509Factory/BEGIN_CERT)
                      (->> (.getEncoded cert)
                           (.encodeToString encoder))
                      #_(X509Factory/END_CERT))])

   ;; accept self signed certs
   ;; https://github.com/apache/httpcomponents-core/blob/master/httpcore5/src/main/java/org/apache/hc/core5/ssl/SSLContextBuilder.java
   ;; https://github.com/apache/httpcomponents-client/blob/master/httpclient5/src/main/java/org/apache/hc/client5/http/ssl/TrustSelfSignedStrategy.java
   (let [ks (KeyStore/getInstance default-keystore-type)
         kmf (KeyManagerFactory/getInstance "SunX509")
         tmf (TrustManagerFactory/getInstance "SunX509")
         ctx (SSLContext/getInstance "DTLS")]
     (.load ks nil nil)
     (.init kmf ks nil)
     (.init tmf ks)
     (let [tms (.getTrustManagers tmf)
           tm (aget tms 0)
           sstm (reify X509TrustManager
                  (checkClientTrusted [_ chain auth-type]
                    (prn ::chain chain (count chain) auth-type)
                    (when-not (= (count chain) 1)
                      (.checkClientTrusted tm chain auth-type)))
                  (checkServerTrusted [_ chain auth-type]
                    (prn ::chain chain (count chain) auth-type)
                    (when-not (= (count chain) 1)
                      (.checkServerTrusted tm chain auth-type)))
                  (getAcceptedIssuers [_] (.getAcceptedIssuers tm)))]
       (aset tms 0 sstm)
       (.init ctx (.getKeyManagers kmf) tms nil)
       tms))

   ;; https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/java.base/share/classes/sun/security/tools/keytool/CertAndKeyGen.java
   ;; create self signed cert
   ;; https://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate/

   (let [dn "cn=jaq, o=alpeware, c=US"
         days 10
         validity (* days 86400000)
         x500name (X500Name. dn)
         cert (CertAndKeyGen. "RSA" "SHA256withRSA")]
     (.generate cert 2048)
     (.getSelfCertificate cert x500name validity))

   (javax.net.ssl.SSLContext/getInstance "DTLS")
   (KeyStore/getInstance "PKCS12")
   (KeyStore/getDefaultType)

   )

(def handshake-status
  {SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING :not-handshaking
   SSLEngineResult$HandshakeStatus/FINISHED :finished
   SSLEngineResult$HandshakeStatus/NEED_TASK :need-task
   SSLEngineResult$HandshakeStatus/NEED_WRAP :need-wrap
   SSLEngineResult$HandshakeStatus/NEED_UNWRAP :need-unwrap
   SSLEngineResult$HandshakeStatus/NEED_UNWRAP_AGAIN :need-unwrap-again})

(defn clarify [hs]
  (get {:need-wrap :encode
        :need-unwrap :decode
        :need-unwrap-again :decode-again}
       hs hs))

(def engine-status
  {SSLEngineResult$Status/BUFFER_OVERFLOW :buffer-overflow
   SSLEngineResult$Status/BUFFER_UNDERFLOW :buffer-underflow
   SSLEngineResult$Status/CLOSED :closed
   SSLEngineResult$Status/OK :ok})

(defn handshake? [^SSLEngine engine]
  (->> ^SSLEngineResult$HandshakeStatus (.getHandshakeStatus engine)
       (get handshake-status)))

(defn result? [^SSLEngineResult result]
  (->> ^SSLEngineResult$Status (.getStatus result)
       (get engine-status)))

(def ^ByteBuffer empty-buffer (ByteBuffer/allocateDirect (* 16 1024)))

(defn handshake!
  ([^SSLEngine engine x]
   (handshake! engine x (.getHandshakeStatus engine)))
  ([^SSLEngine engine x ^SSLEngineResult$HandshakeStatus handshake-status]
   (let [{:nio/keys [selection-key]
          :ssl/keys [packet-size]
          {:keys [reserve commit]
           block-out :block} :nio/out
          {:keys [block decommit]} :nio/in} x
         hs (handshake? engine)
         ;;_ (prn ::hs hs)
         step (condp = hs
                :finished
                (do
                  :finished)

                :need-task
                (do
                  #_(prn ::executing ::task)
                  (-> (.getDelegatedTask engine)
                      ^Runnable (.run))
                  (handshake? engine))

                ;; write data to network
                :need-wrap
                (let [^ByteBuffer dst (reserve)
                      ;;_ (prn ::wrap (handshake? engine) dst)
                      result (try
                               (-> engine
                                   (.wrap empty-buffer dst)
                                   (result?))
                               (catch SSLException e
                                 (prn ::wrap e)
                                 :closed))]
                  (condp = result
                    :buffer-overflow
                    (throw (SSLException. "buffer-overflow"))
                    :buffer-underflow
                    (throw (SSLException. "buffer-underflow"))
                    :closed
                    (throw (SSLException. "close"))
                    :ok
                    (do
                      (.flip dst)
                      (commit dst)
                      #_(prn ::write dst selection-key (.channel selection-key))
                      #_(prn ::written ::hs (nio/datagram-send! x))
                      (nio/datagram-send! x)
                      #_(.interestOps sk SelectionKey/OP_WRITE)
                      (handshake? engine))))

                ;; read data from network
                :need-unwrap
                (let [^ByteBuffer bb (block)]
                  (if (.hasRemaining bb)
                    (let [result (try
                                   (-> engine
                                       (.unwrap bb empty-buffer)
                                       (result?))
                                   (catch SSLException e
                                     (prn ::unwrap e)
                                     :buffer-underflow))]
                      #_(prn ::unwrap ::result result)
                      (condp = result
                        :buffer-overflow
                        (throw (SSLException. "buffer-overflow"))
                        :buffer-underflow
                        (throw (SSLException. "buffer-underflow"))
                        :closed
                        (throw (SSLException. "close"))
                        :ok
                        (do
                          (decommit bb)
                          #_(prn ::read bb selection-key)
                          #_(.interestOps sk SelectionKey/OP_READ)
                          (handshake? engine))))
                    :waiting-for-input))

                ;; ssl engine re-ordered packets
                :need-unwrap-again
                (let [^ByteBuffer bb (block)
                      result (try
                               (-> engine
                                   #_(.unwrap empty-buffer empty-buffer)
                                   (.unwrap bb empty-buffer)
                                   (result?))
                               (catch SSLException e
                                 (prn ::unwrap e)
                                 :buffer-underflow))]
                  (condp = result
                    :buffer-overflow
                    (throw (SSLException. "buffer-overflow"))
                    :buffer-underflow
                    (throw (SSLException. "buffer-underflow"))
                    :closed
                    (throw (SSLException. "close"))
                    :ok
                    (do
                      (decommit bb)
                      #_(.interestOps sk SelectionKey/OP_READ)
                      (handshake? engine))))
                :waiting-for-input
                :noop)]
     (prn ::step ::client (-> engine .getUseClientMode) step empty-buffer)
     (let []
       #_(if-not (contains?  #{:need-task :need-wrap :need-unwrap} step)
         step
         (handshake! engine x (.getHandshakeStatus engine)))
       (if (and (contains?  #{:need-task :need-wrap :need-unwrap :need-unwrap-again} step)
                (-> (block-out) (.hasRemaining) (not)))
         (handshake! engine x (.getHandshakeStatus engine))
         step)))))

#_(
   (in-ns 'jaq.http.xrf.dtls)
   *e
   (.clear empty-buffer)
   (= 1248 (+ 25 763 354 106))
   )

(defn ^SSLContext context []
  (SSLContext/getInstance "DTLS"))

#_(
   (->> (context) (.getDefaultSSLParameters))
   (->> (context) (.getSupportedSSLParameters))
   )
(defn ^SSLContext trust [ctx certs]
  (let [ks (KeyStore/getInstance default-keystore-type)
        kmf (KeyManagerFactory/getInstance "SunX509")
        tmf (TrustManagerFactory/getInstance "SunX509")]
    (.load ks nil nil)
    (doseq [{:cert/keys [alias cert]} certs]
      #_(prn ::cert alias cert)
      (.setCertificateEntry ks alias cert))
    (.init kmf ks nil)
    (.init tmf ks)
    (let [kms (.getKeyManagers kmf)
          km (aget kms 0)
          sskm (proxy [X509ExtendedKeyManager] []
                 (chooseEngineClientAlias [key-types issuers engine]
                   (let [types (->> key-types (set))]
                     #_(prn ::km :client types issuers #_engine)
                     (when (contains? types "RSA")
                       (if (.getUseClientMode engine)
                         "client"
                         "server"))))
                 (chooseEngineServerAlias [key-type issuers engine]
                   #_(prn ::km ::server key-type issuers engine)
                   (when (= key-type "RSA")
                     (if (.getUseClientMode engine)
                       "client"
                       "server")))
                 (getPrivateKey [alias]
                   #_(prn ::km ::private-key alias)
                   (->> certs
                        (filter (fn [{target-alias :cert/alias}] (= alias target-alias)))
                        (first)
                        :cert/private-key))
                 (getCertificateChain [alias]
                   #_(prn ::km ::chain alias)
                   (->> certs
                        (filter (fn [{target-alias :cert/alias}] (= alias target-alias)))
                        (map :cert/cert)
                        (into-array X509Certificate))))
          tms (.getTrustManagers tmf)
          tm (aget tms 0)
          sstm (reify X509TrustManager
                 (checkClientTrusted [_ chain auth-type]
                   #_(prn ::chain chain (count chain) auth-type)
                   (when-not (= (count chain) 1)
                     (.checkClientTrusted tm chain auth-type)))
                 (checkServerTrusted [_ chain auth-type]
                   #_(prn ::chain chain (count chain) auth-type)
                   (when-not (= (count chain) 1)
                     (.checkServerTrusted tm chain auth-type)))
                 (getAcceptedIssuers [_] (.getAcceptedIssuers tm)))]
      (aset kms 0 sskm)
      (aset tms 0 sstm)
      (.init ctx kms tms nil)
      ctx)))

#_(
   (in-ns 'jaq.http.xrf.dtls)
   *e
   (->> k (set))
   (let [kms (trust (context) [])]
     (seq kms))
   (let [km (trust (context) [])]
     (.chooseEngineClientAlias km nil nil nil)
     (.chooseEngineServerAlias km nil nil nil))

   (let [km (trust (context) [{:alias "foo" :cert (self-cert {})}])]
     (.getServerAliases km "RSA" nil))

   (require 'clojure.reflect)
   (require 'clojure.pprint)
   (let [km (proxy [X509ExtendedKeyManager] []
              (chooseEngineClientAlias [key-type issuers engine]
                (throw (Exception. "foo"))
                (prn ::km ::client key-type issuers engine)
                (if (.getUseClientMode engine)
                  "client"
                  "server"))
              (chooseEngineServerAlias [key-type issuers engine]
                (prn ::km ::server key-type issuers engine)
                (if (.getUseClientMode engine)
                  "client"
                  "server")))
         m (proxy-mappings km)]
     #_(update-proxy km (->> m (map (fn [[k v]]
                                    [(->> k (butlast) (apply str)) v]))
                           (into {})))
     (.chooseEngineServerAlias km nil nil nil)
     )


   (seqable? :foo)
   (seqable? nil)
   )

(defn ^SSLEngine ssl-engine [^SSLContext context]
  (.createSSLEngine context))

(defn ^SSLEngine client-mode [^SSLEngine engine client-mode]
  (doto engine
    (.setUseClientMode client-mode)
    #_(.setWantClientAuth true)
    (.setNeedClientAuth true)))

;; aka encode: plain src -> encoded dst
(defn wrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.wrap engine src dst)]))

;; aka decode: encoded src -> plain dst
(defn unwrap! [^SSLEngine engine ^ByteBuffer src ^ByteBuffer dst]
  (let [^SSLEngineResult result (.unwrap engine src dst)]))

(defn configure [^SSLEngine engine packet-size]
  (let [params (.getSSLParameters engine)]
    (.setMaximumPacketSize params packet-size)
    ;; causes duplicate handshake
    (.setEnableRetransmissions params false)
    (.setSSLParameters engine params)
    engine))

(def mode-map {:client true
               :server false})
(def ssl-rf
  (fn [rf]
    (let [eng (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host]
               :nio/keys [channel]
               :ssl/keys [engine certs packet-size mode]
               {:keys [reserve commit block decommit]} :nio/out
               :or {packet-size 1024}
               :as x}]
         (let [mode (get mode-map mode true)]
           (when-not @eng
             (let [engine (or engine
                              (-> (context) (trust certs) (ssl-engine) (client-mode mode) (configure packet-size)))]
               (->> engine (vreset! eng)))
             (when-not mode
               (.beginHandshake @eng))
             (when mode ;; client mode
               (let [dst (reserve)]
                 #_(.beginHandshake @eng)
                 #_(prn ::handshake ::client mode channel)
                 (-> @eng (.wrap empty-buffer dst) #_(result?))
                 (.flip dst)
                 (commit dst))))
           (->> (assoc x :ssl/engine ^SSLEngine @eng)
                (rf acc))))))))

#_(
   (in-ns 'jaq.http.xrf.dtls)

   k
   (contains? #{"RSA"} (->> k (into [])))
   *e

   (let [cert [{:alias "server" :cert (self-cert {})} {:alias "client" :cert (self-cert {})}]
         packet-size 1024
         mode true]
     (-> (context) (trust cert) (ssl-engine) (client-mode mode) (configure packet-size)))

   (let [certs [(self-cert :cert/alias "server")]
         packet-size 1024
         mode true
         ctx (-> (context) (trust certs))]
     (->> ctx (.getDefaultSSLParameters) (.getProtocols) (into []))
     #_(->> ctx (.getSupportedSSLParameters))
     )
   sun.security.ssl.SSLExtension/USE_SRTP

   (let [dst (ByteBuffer/allocate 24024)]
     (-> (context) (ssl-engine) (client-mode true) (configure "jaq.alpeware.com")
         ;;(.getSession) #_(.getPacketBufferSize) (.getApplicationBufferSize)
         (doto (.beginHandshake))
         (.wrap empty-buffer dst)
         #_(result?))
     (.flip dst))

   )
(def handshake-rf
  (fn [rf]
    (let [status (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [host]
               :nio/keys [attachment ^SelectionKey selection-key]
               :ssl/keys [engine]
               {:keys [] block-out :block :as bip} :nio/out
               {:keys [reserve commit decommit] block-in :block} :nio/in
               :as x}]
         (if-not @status
           (let [hs (-> engine (handshake?))]
             (prn ::handshake hs)
             (if-not (contains? #{:finished :not-handshaking} hs)
               (do
                 ;; TODO: skip if out buffer is still full
                 (if (-> (block-out) (.hasRemaining))
                   #_(prn ::written ::hs (nio/datagram-send! x))
                   (nio/datagram-send! x)
                   (handshake! engine x))
                 acc)
               (do
                 (def y x)
                 (let [bb (block-in)]
                   (-> bb (.position (.limit bb)) (decommit)))
                 #_(when (and (not @status)
                              (-> (block) (.hasRemaining)))
                     (nio/datagram-send! x))
                 (when-not @status
                   #_(prn ::handshake hs)
                   (vreset! status hs))
                 (rf acc x))))
           (rf acc x)))))))

#_(
   (->> y (keys))
   (let [{{:keys [reserve commit decommit] block-in :block} :nio/in} y
         {{:keys [] block-out :block :as bip} :nio/out} y]
     (block-out))

   empty-buffer

   )

(defn request-ssl-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          request (volatile! nil)
          requests (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req host port]
               :nio/keys [selection-key]
               :ssl/keys [^SSLEngine engine]
               {:keys [reserve commit block decommit] :as bip} :nio/out
               :as x}]
         (if @once
           (rf acc x)
           (do
             (when-not @requests
               (xrf acc x)
               (when-let [{:http/keys [req] :as xr} (xrf)]
                 (->> req
                      (map (fn [e]
                             (cond
                               (string? e)
                               (-> (.getBytes e)
                                   (ByteBuffer/wrap))

                               (instance? ByteBuffer e)
                               e)))
                      (vreset! requests))))
             (when (and @request (not (.hasRemaining @request)))
               (vreset! request nil))
             (when (and (seq @requests) (not @request))
               (->> @requests
                    (first)
                    (vreset! request))
               (vswap! requests rest))
             (if (and @request (.hasRemaining @request))
               (let [dst (reserve)
                     result (-> engine
                                (.wrap @request dst)
                                (result?))]
                 (condp = result
                   :closed
                   (throw (IllegalStateException. "Connection closed"))

                   ;; wait for socket out to clear
                   :buffer-overflow
                   (do
                     #_(prn result dst @request)
                     acc)

                   :ok
                   (do
                     (.flip dst)
                     (commit dst)
                     (let [written (nio/datagram-send! x)]
                       (prn ::written written host port)
                       (if-not (> written 0)
                         (do
                           (prn ::socket :full host port)
                           ;; socket buffer full so waiting to clear
                           #_(nio/writable! selection-key)
                           acc)
                         (do
                           (recur acc x)))))))
               (->> x
                    (rf acc))))))))))

#_(
   (in-ns 'jaq.http.xrf.dtls)
   *e
   (map (fn [e]
          (cond
            (string? e)
            (-> (.getBytes e)
                (ByteBuffer/wrap))

            (instance? ByteBuffer e)
            e)))
   )


(defn receive-ssl-rf [xf]
  (fn [rf]
    (let [once (volatile! false)
          result (volatile! nil)
          xrf (xf (rf/result-fn))]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:http/keys [req]
               :ssl/keys [^SSLEngine engine]
               :nio/keys [^SelectionKey selection-key]
               {:keys [block decommit commit buf-b] :as bip-in} :nio/in
               {:keys [reserve] :as bip-out} :nio/out
               :as x}]
         (if @once
           (->> x
                (rf acc))
           (let [^ByteBuffer bb (block)
                 ^ByteBuffer scratch (reserve)
                 result (if (.hasRemaining bb)
                          (-> ^SSLEngine engine
                              (.unwrap bb scratch)
                              (result?))
                          #_(try
                            (-> ^SSLEngine engine
                                (.unwrap bb scratch)
                                (result?))
                            (catch SSLException e
                              (prn ::discarding e)
                              #_(-> selection-key (.channel) (.close))
                              #_(.cancel selection-key)
                              (-> bb (.position (.limit bb)) (decommit))
                              :buffer-underflow))
                          :buffer-underflow)]
             (condp = result
               :closed
               (throw (IllegalStateException. "Connection closed"))

               :buffer-underflow
               (do
                 (if-not (and (.hasRemaining bb) (> (.limit buf-b) 0))
                   acc
                   ;; compact & merge region a and b of bip
                   (do
                     (prn ::buffer-underflow ::compacting bb buf-b scratch)
                     (.put scratch bb)
                     (decommit bb)
                     (let [^ByteBuffer bb2 (block)]
                       (.put scratch bb2)
                       (decommit bb2)
                       (.flip scratch)
                       (let [^ByteBuffer bb3 ((:reserve bip-in))]
                         (.put bb3 scratch)
                         (.flip bb3)
                         (commit bb3)))
                     acc)))

               :buffer-overflow
               (prn ::buffer-overflow bb scratch)
               acc

               :ok
               (do
                 (decommit bb)
                 (.flip scratch)
                 (when (.hasRemaining scratch)
                   (loop []
                     (let [b (.get scratch)]
                       (->> (assoc x
                                   :context/remaining (.remaining scratch)
                                   :byte b)
                            (xrf acc)))
                     (when (and (.hasRemaining scratch) (not (xrf)))
                       (recur))))
                 (cond
                   (xrf)
                   (do
                     (vreset! once true)
                     (rf acc (xrf)))

                   (not (.hasRemaining bb))
                   acc

                   :else
                   (recur acc x)))))))))))

#_(
   *e
   *ns*
   (require 'jaq.http.xrf.dtls :reload)

   (in-ns 'jaq.http.xrf.dtls)
   *e

   (let [{:ssl/keys [engine]} {:ssl/engine :foo}]
     engine)
   )
