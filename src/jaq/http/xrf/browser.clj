(ns jaq.http.xrf.browser
  (:require
   [clojure.java.io :as io]
   [clojure.string :as string]
   [clojure.set :as set]
   [clojure.data.json :as json]
   [clojure.tools.reader :as reader]
   [clojure.tools.reader.reader-types :as readers]
   [cljs.tagged-literals :as tags]
   [clojure.edn :as edn]
   [cljs.util :as util]
   [cljs.compiler :as comp]
   [cljs.analyzer :as ana]
   [cljs.analyzer.api :as ana-api]
   [cljs.env :as env]
   [cljs.js-deps :as deps]
   [cljs.closure :as cljsc]
   [cljs.source-map :as sm]
   [cljs.build.api :as build]
   [cljs.repl.browser :as browser]
   [cljs.repl.server :as server]
   [cljs.repl :as repl]
   [cljs.stacktrace :as st]
   [cljs.analyzer :as ana]
   [cljs.closure :as cljsc])
  (:import
   [java.io File PushbackReader FileWriter PrintWriter]
   [java.net URL]
   [java.util Base64]
   [java.util.concurrent.atomic AtomicLong]
   [java.util.concurrent Executors ConcurrentHashMap]
   [clojure.lang IExceptionInfo]
   [com.google.common.base Throwables]))


;; compiler state
(def cenv (atom nil))
(def cljs-ns (atom 'cljs.user))

;; TODO: switch server
;; TODO: change read-print-eval loop

(defn repl-env*
  [{:keys [output-dir] :as opts}]
  (merge {:working-dir (->> [".repl" (util/clojurescript-version)]
                            (remove empty?) (string/join "-"))
          :static-dir (cond-> ["." "out/"] output-dir (conj output-dir))
          :preloaded-libs []
          :src "src/"}
         opts))

;; fns from cljs.repl
(defn bytes-to-base64-str
  "Convert a byte array into a base-64 encoded string."
  [^bytes bytes]
  (.encodeToString (Base64/getEncoder) bytes))

;; TODO: return a string
(defn load-sources
  "Load the compiled `sources` into the REPL."
  [repl-env sources opts]
  (when (:output-dir opts)
    ;; REPLs that read from :output-dir just need to add deps,
    ;; environment will handle actual loading - David
    (let [sb (StringBuffer.)]
      (doseq [source sources]
        (with-open [rdr (io/reader (:url source))]
          (.append sb (cljsc/add-dep-string opts source))))
      (when (:repl-verbose opts)
        (println (.toString sb)))
      #_(-evaluate repl-env "<cljs repl>" 1 (.toString sb))
      (.toString sb))
    ;; REPLs that stream must manually load each dep - David
    #_(doseq [{:keys [url provides]} sources]
        (-load repl-env provides url))))

(defn load-cljs-loader
  "Compile and load the cljs.loader namespace if it's present in `sources`."
  [repl-env sources opts]
  (when-let [source (first (filter #(= (:ns %) 'cljs.loader) sources))]
    (cljsc/compile-loader sources opts)
    (load-sources repl-env [source] opts)))

(defn env->opts
  "Returns a hash-map containing all of the entries in [repl-env], translating
  :working-dir to :output-dir."
  ([repl-env] (env->opts repl-env nil))
  ([repl-env opts]
   ;; some bits in cljs.closure use the options value as an ifn :-/
   (-> (into {} repl-env)
       (assoc :optimizations
              (or (:optimizations opts) (get repl-env :optimizations :none)))
       (assoc :output-dir
              (or (:output-dir opts) (get repl-env :working-dir ".repl"))))))

(defn add-url [ijs]
  (cond-> ijs
    (not (contains? ijs :url))
    (assoc :url (io/resource (:file ijs)))))

(defn ns->input [ns opts]
  (or (some-> (util/ns->source ns) (ana/parse-ns opts))
      (some-> (get-in @env/*compiler* [:js-dependency-index (str ns)]) add-url)
      (some-> (deps/find-classpath-lib ns))
      (throw
       (ex-info (str ns " does not exist")
                {::error :invalid-ns}))))

(defn compilable? [input]
  (contains? input :source-file))

(defn load-namespace
  "Load a namespace and all of its dependencies into the evaluation environment.
  The environment is responsible for ensuring that each namespace is
  loaded once and only once. Returns the compiled sources."
  ([repl-env ns] (load-namespace repl-env ns nil))
  ([repl-env ns opts]
   (let [ns      (if (and (seq? ns) (= (first ns) 'quote)) (second ns) ns)
         sources (seq
                  (when-not (ana/node-module-dep? ns)
                    (let [input (ns->input ns opts)]
                      (if (compilable? input)
                        (->> (cljsc/compile-inputs [input]
                                                   (merge (env->opts repl-env) opts))
                             (remove (comp #{["goog"]} :provides)))
                        (map #(cljsc/source-on-disk opts %)
                             (cljsc/add-js-sources [input] opts))))))]
     (when (:repl-verbose opts)
       (println (str "load-namespace " ns " , compiled:") (map :provides sources)))
     (load-sources repl-env sources opts)
     #_sources)))

(defn load-dependencies
  "Compile and load the given `requires` and return the compiled sources."
  ([repl-env requires]
   (load-dependencies repl-env requires nil))
  ([repl-env requires opts]
   (doall (mapcat #(load-namespace repl-env % opts) (distinct requires)))))

;; TODO: rename to compile form
(defn evaluate-form
  "Evaluate a ClojureScript form in the JavaScript environment. Returns a
  string which is the ClojureScript return value. This string may or may
  not be readable by the Clojure reader."
  ([repl-env env filename form]
   (evaluate-form repl-env env filename form identity))
  ([repl-env env filename form wrap]
   (evaluate-form repl-env env filename form wrap repl/*repl-opts*))
  ([repl-env env filename form wrap opts]
   (binding [ana/*cljs-file* filename]
     (let [env (merge env
                      {:root-source-info {:source-type :fragment
                                          :source-form form}
                       :repl-env repl-env})
           def-emits-var (:def-emits-var opts)
           backup-comp @env/*compiler*
           ->ast (fn [form]
                   (binding [ana/*analyze-deps* false]
                     (ana/analyze (assoc env :def-emits-var def-emits-var)
                                  (wrap form) nil opts)))
           ast (->ast form)
           ast (if-not (#{:ns :ns*} (:op ast))
                 ast
                 (let [ijs (ana/parse-ns [form])]
                   (cljsc/handle-js-modules opts
                                            (deps/dependency-order
                                             (cljsc/add-dependency-sources [ijs] opts))
                                            env/*compiler*)
                   (binding [ana/*check-alias-dupes* false]
                     (ana/no-warn (->ast form))))) ;; need new AST after we know what the modules are - David
           wrap-js
           ;; TODO: check opts as well - David
           (if (:source-map repl-env)
             (binding [comp/*source-map-data*
                       (atom {:source-map (sorted-map)
                              :gen-line 0})
                       comp/*source-map-data-gen-col* (AtomicLong.)]
               (let [js (comp/emit-str ast)
                     t (System/currentTimeMillis)]
                 (str js
                      "\n//# sourceURL=repl-" t ".js"
                      "\n//# sourceMappingURL=data:application/json;base64,"
                      (bytes-to-base64-str
                       (.getBytes
                        (sm/encode
                         {(str "repl-" t ".cljs")
                          (:source-map @comp/*source-map-data*)}
                         {:lines (+ (:gen-line @comp/*source-map-data*) 3)
                          :file (str "repl-" t ".js")
                          :sources-content
                          [(or (:source (meta form))
                               ;; handle strings / primitives without metadata
                               (with-out-str (pr form)))]})
                        "UTF-8")))))
             (comp/emit-str ast))

           sources
           ;; NOTE: means macros which expand to ns aren't supported for now
           ;; when eval'ing individual forms at the REPL - David
           (when (#{:ns :ns*} (:op ast))
             (let [ast (try
                         (ana/no-warn (ana/analyze env form nil opts))
                         (catch Exception e
                           (reset! env/*compiler* backup-comp)
                           (throw e)))
                   sources (load-dependencies repl-env
                                              (into (vals (:requires ast))
                                                    (distinct (vals (:uses ast))))
                                              opts)]
               (apply str sources)
               ;; TODO: cljs loader not needed?
               #_(load-cljs-loader repl-env sources opts)))
           cns (reset! cljs-ns ana/*cljs-ns*)]
       #_(when repl/*cljs-verbose*
           (repl/err-out (println wrap-js)))
       {:js wrap-js :deps sources :cljs-ns cns}
       #_[filename (:line (meta form)) wrap-js sources]))))

;; provides: cljsc options, compiler-env, env, bunch of bindings, init, setup, eval form
(defn repl*
  [repl-env {:keys [init inits need-prompt quit-prompt prompt flush read eval print caught reader
                    print-no-newline source-map-inline wrap repl-requires ::fast-initial-prompt?
                    compiler-env bind-err]
             :or {need-prompt #(if (readers/indexing-reader? *in*)
                                 (== (readers/get-column-number *in*) 1)
                                 (identity true))
                  ;;fast-initial-prompt? false
                  ;;quit-prompt repl/repl-title
                  ;;prompt repl/repl-prompt
                  ;;flush flush
                  ;;read repl/repl-read
                  ;;eval repl/eval-cljs
                  ;;print println
                  caught repl/repl-caught
                  reader #(readers/source-logging-push-back-reader
                           *in*
                           1 "<NO_SOURCE_FILE>")
                  ;;print-no-newline print
                  source-map-inline true
                  repl-requires '[[cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                                  [cljs.pprint :refer [pprint] :refer-macros [pp]]]
                  bind-err true}
             :as opts}]
  (let [repl-opts repl-env #_(repl/-repl-options repl-env)
        repl-requires (into repl-requires (:repl-requires repl-opts))
        {:keys [analyze-path repl-verbose warn-on-undeclared special-fns
                checked-arrays static-fns fn-invoke-direct]
         :as opts
         :or   {warn-on-undeclared true
                repl-verbose true}}
        (merge
         {:def-emits-var true}
         (cljsc/add-implicit-options
          (merge-with (fn [a b] (if (nil? b) a b))
                      repl-opts
                      opts
                      {:prompt prompt
                       :need-prompt need-prompt
                       :flush flush
                       :read read
                       :print print
                       :caught caught
                       :reader reader
                       :print-no-newline print-no-newline
                       :source-map-inline source-map-inline})))
        ;;cenv (or compiler-env env/*compiler* (env/default-compiler-env* opts))
        env {:context :expr :locals {}}
        special-fns (merge repl/default-special-fns special-fns)
        is-special-fn? (set (keys special-fns))]
    (reset! cenv (or compiler-env env/*compiler* (env/default-compiler-env* opts)))
    ;; analyze
    (binding [;;repl/*repl-env* repl-env
              ana/*unchecked-if* false
              ana/*unchecked-arrays* false
              ana/*cljs-ns* @cljs-ns
              repl/*cljs-verbose* repl-verbose
              ana/*cljs-warnings*
              (let [warnings (opts :warnings)]
                (merge
                 ana/*cljs-warnings*
                 (if (or (true? warnings)
                         (false? warnings))
                   (zipmap (keys ana/*cljs-warnings*) (repeat warnings))
                   warnings)
                 (zipmap
                  [:unprovided :undeclared-var
                   :undeclared-ns :undeclared-ns-form]
                  (repeat (if (false? warnings)
                            false
                            warn-on-undeclared)))
                 {:infer-warning false}))
              ana/*checked-arrays* false
              ana/*cljs-static-fns* static-fns
              ana/*fn-invoke-direct* (and static-fns fn-invoke-direct)]
      (env/with-compiler-env cenv
        (when analyze-path
          (if (vector? analyze-path)
            (run! #(repl/analyze-source % opts) analyze-path)
            (repl/analyze-source analyze-path opts)))))
    ;; TODO: do we need this?
    #_(repl/evaluate-form repl-env env "<cljs repl>"
                          `(~'set! ~'cljs.core/*print-namespace-maps* true)
                          identity opts)
    ;; TODO: this is causing stack overflow
    #_(init)
    #_(let [repl-requires '[[cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                            [cljs.pprint :refer [pprint] :refer-macros [pp]]
                            #_[clojure.browser.repl]
                            #_[clojure.browser.repl.preload]]]
        (print ::requires repl-requires)
        (repl/evaluate-form repl-env env "<cljs repl>"
                            `(~'ns ~'cljs.user
                              (:require ~@repl-requires))
                            identity opts))
    #_(repl/evaluate-form repl-env env "<cljs repl>"
                          (with-meta
                            `(~'ns ~'cljs.user
                              (:require ~@repl-requires))
                            {:line 1 :column 1})
                          identity opts)
    #_(repl/run-inits repl-env inits)
    #_(maybe-load-user-file)
    #_(when-let [user-resource (util/ns->source 'user)]
        (when (= "file" (.getProtocol ^URL user-resource))
          (repl/load-file repl-env (io/file user-resource) opts)))
    {:opts opts
     ;;:compiler-env (reset! *compiler* compiler-env)
     :compile
     (fn [opts input]
       (env/with-compiler-env cenv
         (binding [;;repl/*repl-env* repl-env
                   ana/*unchecked-if* false
                   ana/*unchecked-arrays* false
                   ana/*cljs-ns* @cljs-ns
                   ana/*cljs-warnings*
                   (let [warnings (opts :warnings)]
                     (merge
                      ana/*cljs-warnings*
                      (if (or (true? warnings)
                              (false? warnings))
                        (zipmap (keys ana/*cljs-warnings*) (repeat warnings))
                        warnings)
                      (zipmap
                       [:unprovided :undeclared-var
                        :undeclared-ns :undeclared-ns-form]
                       (repeat (if (false? warnings)
                                 false
                                 warn-on-undeclared)))
                      {:infer-warning false}))
                   ana/*checked-arrays* false
                   ana/*cljs-static-fns* static-fns
                   ana/*fn-invoke-direct* (and static-fns fn-invoke-direct)]
           (let [form (binding [*ns* (create-ns ana/*cljs-ns*)
                                reader/resolve-symbol ana/resolve-symbol
                                reader/*data-readers* tags/*cljs-data-readers*
                                reader/*alias-map*
                                (apply merge
                                       ((juxt :requires :require-macros)
                                        (ana/get-namespace ana/*cljs-ns*)))]
                        (try
                          (read-string {:read-cond :allow :features #{:cljs}} input)
                          (catch Throwable e
                            #_(throw (ex-info nil {:clojure.error/phase :read-source} e))
                            (prn (ex-info nil {:clojure.error/phase :read-source} e)))))]
             (prn ::form form)
             (try
               (if (and (seq? form) (is-special-fn? (first input)))
                 (do
                   (print ::special (first form))
                   ;; TODO: handle special fns
                   ((get special-fns (first form)) repl-env env input opts)
                   (print nil))
                 (evaluate-form repl-env
                                (assoc env :ns (ana/get-namespace ana/*cljs-ns*))
                                "<cljs repl>"
                                form
                                identity
                                opts))
               (catch Throwable e
                 (caught e repl-env opts)
                 nil)))
           )))}))

(def env-rf
  (fn [rf]
    (let [env (volatile! nil)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:repl/keys [opts]
               :as x}]
         (when-not @env
           (-> (repl-env* opts)
               (repl* {})
               (->> (vreset! env))))
         (->> (assoc x :repl/env @env)
              (rf acc)))))))

(def compile-rf
  (fn [rf]
    (let [init (volatile! false)]
      (fn
        ([] (rf))
        ([acc] (rf acc))
        ([acc {:repl/keys [env input]
               :as x}]
         (let [{:keys [compile opts]} env
               {:keys [js deps cljs-ns]} (compile opts input)
               js (if deps (str deps js) js)]
           (->> (assoc x
                       :repl/js js
                       :repl/cljs-ns cljs-ns)
                (rf acc))))))))

;; TODO: implement special fns

#_(
   (into [] compile-rf [{:repl/input "(range 10)"}])

   (into [] (comp
             (map (fn [x] {:repl/input (str x)}))
             env-rf
             compile-rf)
         ['(ns foo.bar) '(ns foo.baz) '(range 10)])

   (into [] (comp
             (map (fn [x] {:repl/input (str x)}))
             env-rf
             compile-rf
             (map (fn [x] (select-keys x [:repl/js :repl/cljs-ns]))))
         ['(cljs.core/range 10)])

   (into [] (comp
             (map (fn [x] {:repl/input (str x)}))
             env-rf
             compile-rf
             (map (fn [x] (select-keys x [:repl/js :repl/cljs-ns]))))
         ['(pr-str (read-string {:read-cond :allow} "#?(:clj :clj :cljs :cljs)"))])

   (pr-str (read-string {:read-cond :allow} "#?(:clj :clj :cljs :cljs)"))

   (pr-str (cljs.reader/read-string {:read-cond :allow} "#?(:clj :clj :cljs :cljs)"))

   (cljs.reader/read-string {:read-cond :preserve} "#?(:clj :clj :cljs :cljs)")

   (read-string {:read-cond :preserve} "#?(:clj :clj :cljs :cljs)")
   (read-string {:read-cond :allow} "#?(:clj :clj :cljs :cljs)")
   (read-string {:read-cond :allow :features #{:cljs}} "#?(:cljs :cljs)")
   (read-string {:read-cond :allow :features #{:cljs}} "#?(:cljs :cljs :clj :clj :default :default)")
   (read-string {:read-cond :allow :features #{:cljs}} "#?(:clj :clj :cljs :cljs :default :default)")

   (cljs.reader/read-string "(+ 1 1)")

   (require 'cljs.core)
   (require 'cljs.reader)

   (defmacro if-cljs [then else]
     (if (:ns &env) then else))

   (if-cljs true false)

   (into [] (comp
             (map (fn [x] {:repl/input (str x)}))
             env-rf
             compile-rf)
         ['(ns cljs.user (:require [cljs.core]
                                   [cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                                   [cljs.pprint :refer [pprint] :refer-macros [pp]]))
          ;;'(ns foo.bar)
          '(range 10)])

   @cljs-ns

   (-> @cenv (keys))
   (-> @cenv :cljs.analyzer/namespaces)

   ;; TODO: compiler state not saved. Save and restore bindings?

   (into [] compile-rf [{:repl/input (str '(ns cljs.user (:require [cljs.core]
                                                                   [cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                                                                   [cljs.pprint :refer [pprint] :refer-macros [pp]])))}])

   (-> (repl-env* {})
       (repl* {})
       #_(->> (vreset! env)))

   )

#_(
   *e
   (in-ns 'jaq.http.xrf.browser)
   (require 'jaq.http.xrf.browser :reload)
   *ns*

   ;; start cljs repl providing it's own server
   (def repl-env (repl-env* {:port 10010 :launch-browser false :host "0.0.0.0" :repl-verbose true}))
   (def e (repl* repl-env {}))

   (-> e :opts :repl-verbose)

   (let [input '(ns cljs.user (:require [cljs.core]
                                        [cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                                        [cljs.pprint :refer [pprint] :refer-macros [pp]]))
         {:keys [compile compiler-env opts]} e]
     (compile compiler-env opts (str input)))

   *ns*
   *e
   (+ 1 1)
   (require 'cljs.core)
   (pr-str (range 10))

   (ns foo.bar (:require [cljs.core]))
   (ns test.dom (:require [clojure.browser.dom :as dom]))
   (dom/get-element "app")
   (dom/append (dom/get-element "app")
               (dom/element "ClojureScript is all up in your DOM."))


   browser/cljs-ns

   (-> @browser/cenv :cljs.anaylzer/externs)

   (ns cljs.user (:require [cljs.core]))

   (ns cljs.user (:require [cljs.core]
                           [cljs.repl :refer-macros [source doc find-doc apropos dir pst]]
                           [cljs.pprint :refer [pprint] :refer-macros [pp]]))

   (require 'jaq.http.xrf.client)
   ;; compile cljs
   (cljsc/build "src"
                {:optimizations :none
                 :output-dir "out"
                 ;;:output-to "out/hello.js"
                 :source-map true}
                cenv)

   (reset! cenv (or env/*compiler* (env/default-compiler-env* opts)))
   (in-ns 'jaq.http.xrf.browser)
   (cljsc/build "src"
                {:optimizations #_:advanced #_:simple :none
                 :output-dir "out"
                 ;;:output-to "out/app.js"
                 ;;:fingerprint true
                 :verbose true
                 :source-map true #_"out/app.js.map"
                 :infer-externs true
                 }
                cenv)

   (cljsc/build "src"
                {:optimizations :advanced #_:simple #_:none
                 :output-dir "tmp"
                 :output-to "tmp/app.js"
                 :fingerprint true
                 :verbose true
                 :source-map #_true "tmp/app.js.map"
                 :closure-defines {"goog.DEBUG" false}
                 ;;:infer-externs true
                 :libs ["tmp/inferred_externs.js"]
                 }
                cenv)

   (cljsc/build "src"
                {:optimizations :advanced #_:simple #_:none
                 :output-dir "tmp"
                 :output-to "tmp/app.js"
                 :fingerprint true
                 :verbose true
                 :source-map #_true "tmp/app.js.map"
                 :closure-defines {"goog.DEBUG" false}
                 :infer-externs true
                 ;;:libs ["tmp/inferred_externs.js"]
                 })
   *ns*
   *e

   )
