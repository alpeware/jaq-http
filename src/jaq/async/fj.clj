(ns jaq.async.fj
  (:import
   [java.util.concurrent ForkJoinPool ForkJoinTask]))

(def processors (.availableProcessors (Runtime/getRuntime)))

(def thread-factory ForkJoinPool/defaultForkJoinWorkerThreadFactory)

;;; adapted from clojure.core.reducers
(def pool
  (delay (ForkJoinPool. processors thread-factory nil true)))

(defn ^ForkJoinTask task [^Callable f]
  (ForkJoinTask/adapt f))

(defn invoke [f]
  (if (ForkJoinTask/inForkJoinPool)
    (f)
    (.invoke ^ForkJoinPool @pool ^ForkJoinTask (task f))))

(defn fork [task] (.fork ^ForkJoinTask task))

(defn join [task] (.join ^ForkJoinTask task))

;;; threads
(defn thread-call [^Runnable f]
  (doto (Thread. f)
      (.start)))

;;; adapted from clojure.core.async
(defmacro thread [& body]
  `(thread-call (^:once fn* [] ~@body)))

#_(
   (thread (prn :foo))
   )


#_(
   *ns*
   (in-ns 'jaq.async.fj)
   processors
   @pool
   (invoke (fn [] :foo))
   )
