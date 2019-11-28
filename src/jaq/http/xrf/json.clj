(ns jaq.http.xrf.json
  "Transducers to handle JSON data."
  (:require
   [taoensso.tufte :as tufte :refer [defnp fnp p]]))

(defnp mapper
  "Maps a vec of chars in hex ints to a character."
  [[a b c d]]
  (-> (str (char a) (char b) (char c) (char d))
      (Integer/parseInt 16)
      (char)))

#_(
   (mapper  (->> "0092" (map char)))

   (->> "005C"
        (map char)
        (apply str)
        ((fn [e] (Integer/parseInt e 16)))
        (char))

   (let [s (str \0 \0 \9 \2)]
     (char (Integer/parseInt s 16)))
   )


(defn decoder
  "Transducer to perform JSON decoding."
  []
  (fn [rf]
    (let [decode (volatile! false)
          hex (volatile! false)
          done (volatile! false)
          vacc (volatile! [])
          v (volatile! [])
          length (volatile! 0)
          assoc-fn (fn [acc x c]
                     (vreset! decode false)
                     (->> (assoc x :char c)
                          (rf acc)))]
      (fnp decode-rf
           ([] (rf))
           ([acc] (rf acc))
           ([acc {:keys [index char]
                  {:keys [content-length]} :headers
                  :as x}]
            (vswap! length inc)
            (cond
              @done
              (rf acc x)

              (and (= char \") @decode)
              #_(assoc-fn acc x \")
              (assoc-fn acc x :quotes)

              (and (= char \/) @decode)
              (assoc-fn acc x \/)

              ;; NOTE: using \ seems to confuse smartparens
              (and (= (int char) 92) @decode) ;; \
              (assoc-fn acc x (clojure.core/char 92))

              (and (= char \b) @decode (not @hex))
              (assoc-fn acc x \backspace)

              (and (= char \f) @decode (not @hex))
              (assoc-fn acc x \formfeed)

              (and (= char \n) @decode (not @hex))
              (assoc-fn acc x \newline)

              (and (= char \r) @decode (not @hex))
              (assoc-fn acc x \return)

              (and (= char \t) @decode (not @hex))
              (assoc-fn acc x \tab)

              (and (= char \u) @decode (not @hex))
              (do
                (vreset! hex true)
                acc)

              (and (= (int char) 92) (not @decode)) ;; \
              (do
                (vreset! decode true)
                acc)

              @decode
              (do
                (vswap! vacc conj char)
                (when (-> @vacc (count) (= 4))
                  (let [c (->> @vacc (mapper))
                        c (if (= c \") :quotes c)]
                    (vreset! decode false)
                    (vreset! hex false)
                    (vreset! vacc [])
                    (assoc-fn acc x c))))

              :else
              (assoc-fn acc x char)))))))

#_(
   *e
   *ns*
   (char (int 92))
   (prn \\)
   (require 'jaq.http.xrf.json)
   (in-ns 'jaq.http.xrf.json)

   (let [original "\\u005C\\\"\\\"\\/\\\\"
         original "[\"\\\"\"]"
         encoded original
         xform (comp
                jaq.http.xrf.rf/index
                (map (fn [x]
                       (assoc x :headers {:content-length (count encoded)})))
                (decoder))
         decoded (->> (sequence xform encoded)
                      (map :char)
                      (apply str))]
     [original encoded decoded (= original decoded)])
   )

(defn process [& [keyword-fn]]
  (let [keyword-fn (or keyword-fn keyword)]
    (fn [rf]
      (let [json (volatile! nil)
            open (volatile! [])
            pending (volatile! nil)
            done (volatile! false)
            vacc (volatile! [])
            val (volatile! nil)
            null (volatile! false)
            map-name (volatile! [])
            fraction (volatile! false)
            k :json
            assoc-fn (fn [acc x] (->>
                                  @json
                                  (assoc x k)
                                  (rf acc)))
            done-fn (fn [acc x]
                      (if (empty? @open)
                        (do
                          (vreset! json @val)
                          (vreset! done true)
                          (assoc-fn acc x))
                        acc))]
        (fnp process-rf
             ([] (rf))
             ([acc] (rf acc))
             ([acc {:keys [char] :as x}]
              #_(prn ::open @open ::pending @pending ::map-name @map-name ::x x)
              (cond
                @done
                (assoc-fn acc x)

                ;; arrays
                (and (= char \[)
                     (not= (peek @open) :string))
                (do
                  (vswap! open conj :array)
                  (vswap! pending conj [])
                  acc)

                (and (= char \])
                     (= (peek @open) :array))
                (let [arr (cond
                            (and (not @null) (nil? @val))
                            (peek @pending)
                            (and @null (nil? @val))
                            (do
                              (vreset! null false)
                              (-> (peek @pending)
                                  (conj @val)))
                            :else
                            (-> (peek @pending)
                                (conj @val)))]
                  (vswap! open pop)
                  (vswap! pending pop)
                  (vreset! val arr)
                  (done-fn acc x))

                (and (or (= char \]) (= char \}))
                     (= (peek @open) :number))
                (let [s (->> @vacc (apply str))
                      n (cond
                          @fraction
                          (Double/valueOf s)
                          (< (count s) 18)
                          (Long/valueOf s)
                          :else
                          (bigint s))]
                  (vreset! fraction false)
                  (vreset! vacc [])
                  (vswap! open pop)
                  ;; TODO: DRY more
                  (if (= (peek @open) :map)
                    (let []
                      (vreset! val (-> (peek @pending)
                                       (conj {(peek @map-name) n})))
                      (vswap! map-name pop))
                    (let []
                      (vreset! val (-> (peek @pending)
                                       (conj n)))))
                  (vswap! open pop)
                  (vswap! pending pop)
                  (done-fn acc x))

                ;; maps
                (and (= char \{)
                     (not= (peek @open) :string))
                (do
                  (vswap! open conj :map)
                  (vswap! pending conj {})
                  acc)

                (and (= char \})
                     (= (peek @open) :map))
                (let [m (if (and (seq @map-name) (not (nil? @val)))
                          (let [mn (peek @map-name)]
                            (vswap! map-name pop)
                            (-> (peek @pending)
                                (conj {mn @val})))
                          (-> (peek @pending) ;; empty map
                              (conj {})))]
                  (vswap! open pop)
                  (vswap! pending pop)
                  (vreset! val m)
                  (done-fn acc x))

                ;; string values
                (and (= char \")
                     (not= (peek @open) :string))
                (do
                  (vswap! open conj :string)
                  acc)

                (and (= char \")
                     (= (peek @open) :string))
                (do
                  (vswap! open pop)
                  (->> @vacc (apply str) (vreset! val))
                  (vreset! vacc [])
                  acc)

                ;; separator for arrays
                (and (= char \,)
                     (= (peek @open) :array))
                (let [arr (-> (peek @pending)
                              (conj @val))]
                  (vswap! pending pop)
                  (vswap! pending conj arr)
                  (vreset! val nil)
                  acc)

                ;; separator for maps
                (and (= char \,)
                     (= (peek @open) :map))
                (let [m (-> (peek @pending)
                            (conj {(peek @map-name) @val}))]
                  (vswap! map-name pop)
                  (vswap! pending pop)
                  (vswap! pending conj m)
                  (vreset! val nil)
                  acc)

                ;; separator for map k/v
                (and (= char \:)
                     (= (peek @open) :map))
                (do
                  (vswap! map-name conj (keyword-fn @val))
                  (vreset! val nil)
                  acc)

                ;; separator for numbers
                (and (= char \,)
                     (= (peek @open) :number))
                (let [s (->> @vacc (apply str))
                      n (cond
                          @fraction
                          (Double/valueOf s)
                          (< (count s) 18)
                          (Long/valueOf s)
                          :else
                          (bigint s))]
                  (vreset! fraction false)
                  (vreset! val n)
                  (vreset! vacc [])
                  (vswap! open pop)
                  ;; TODO: DRY more
                  (if (= (peek @open) :map)
                    (let [m (-> (peek @pending)
                                (conj {(peek @map-name) @val}))]
                      (vswap! map-name pop)
                      (vswap! pending pop)
                      (vswap! pending conj m))
                    (let [arr (-> (peek @pending)
                                  (conj @val))]
                      (vswap! pending pop)
                      (vswap! pending conj arr)))
                  (vreset! val nil)
                  acc)

                (and (contains? #{\space \return \tab \newline} char)
                     (not= (peek @open) :string))
                acc

                ;; start of a number
                (and (not= (peek @open) :number)
                     (not= (peek @open) :string)
                     (contains? #{\- \0 \1 \2 \3 \4 \5 \6 \7 \8 \9} char))
                (do
                  (vswap! open conj :number)
                  (vswap! vacc conj char))

                ;; fraction
                (and (contains? #{\. \e \E} char)
                     (not @fraction)
                     (= (peek @open) :number))
                (do
                  (vreset! fraction true)
                  (vswap! vacc conj char))

                ;; booleans
                (and (not= (peek @open) :string)
                     (empty? @vacc)
                     (= char \t))
                (do
                  (vswap! open conj :true)
                  (vswap! vacc conj char))

                (and (= (peek @open) :true)
                     (= char \e))
                (do
                  (vswap! open pop)
                  (vreset! val true)
                  (vreset! vacc []))

                (and (not= (peek @open) :string)
                     (empty? @vacc)
                     (= char \f))
                (do
                  (vswap! open conj :false)
                  (vswap! vacc conj char))

                (and (= (peek @open) :false)
                     (= char \e))
                (do
                  (vswap! open pop)
                  (vreset! val false)
                  (vreset! vacc []))

                ;; nil
                (and (not= (peek @open) :string)
                     (empty? @vacc)
                     (= char \n))
                (do
                  (vswap! open conj :null)
                  (vswap! vacc conj char))

                (and (= (peek @open) :null)
                     (= (count @vacc) 3)
                     (= char \l))
                (do
                  (vswap! open pop)
                  (vreset! val nil)
                  (vreset! null true)
                  (vreset! vacc []))

                (and (= char :quotes))
                (do
                  (vswap! vacc conj \")
                  acc)

                :else
                (do
                  (vswap! vacc conj char)
                  acc))))))))

#_(
   *ns*
   (require 'jaq.http.xrf.json :reload)
   (in-ns 'jaq.http.xrf.json)
   *e

   (let [;;original ["foo" ["a" ["b" [{:bar "baz"}]]]]
         ;;original [1 2 "foo" 3 {:foo -2.2}]
         ;;original {:bar {:foo {:bar "baz"}}}
         ;;original {:bar {:foo [1]}}
         ;;original {:foo true :bar [true false nil]}
         original {:foo.1 false}
         ;;original []
         encoded (clojure.data.json/write-str original)
         xform (comp
                jaq.http.xrf.rf/index
                (decoder)
                (process))
         decoded (->> (sequence xform encoded) (first) :json)]
     [original encoded decoded (= original decoded)])


   (let [;;original ["foo" ["a" ["b" [{:bar "baz"}]]]]
         ;;original [1 2 "foo" 3 {:foo -2.2}]
         ;;original [1.12]
         ;;original {:bar {:foo {:bar "baz"}}}
         original {:foo true :bar [true false nil]}
         ;;encoded (clojure.data.json/write-str original)
         encoded test-string
         ;;encoded ts
         ;;encoded "[\"\\\"\"]"
         ;;encoded (str "[\"\\\\\",\"\\b\\f\\n\\r\\t\",\"/ & \\/\"]")
         xform (comp
                jaq.http.xrf.rf/index
                (decoder)
                (process))
         decoded (->> (sequence xform encoded) (first) :json)]
     decoded)
   (clojure.data.json/read-str test-string)

   (Double/valueOf "1e1")

   (let [buf "[\"foo\", \"bar\"]"
         ;;buf "{\"foo\": \"bar\",  \"bar\": \"baz\"}"
         ;;buf "{\"foo\": \"bar\",  \"bar\": [\"baz\"]}"
         rf (let [result (volatile! nil)]
              (fn
                ([] @result)
                ([acc] acc)
                ([acc x] (vreset! result x) acc)))
         xform (comp
                jaq.http.xrf.rf/index
                (decoder)
                (process))
         xf (xform rf)]
     (run! (fn [x] (tufte/p :xf (xf nil x))) buf)
     (rf))

   (-> [[] [:foo]]
       (peek)
       (conj :bar))


   (->> (conj [] :foo) (pop))

   (def ts "[

1066,
1e1,
0.1e1,
1e-1,
1e00,2e+00,2e-00
,\"rosebud\"

    ]")

   (def test-string
     "[
    \"JSON Test Pattern pass1\",
    {\"object with 1 member\":[\"array with 1 element\"]},
    {},
    [],
    -42,
    true,
    false,
    null,
    {
        \"integer\": 1234567890,
        \"real\": -9876.543210,
        \"e\": 0.123456789e-12,
        \"E\": 1.234567890E+34,
        \"\":  23456789012E66,
        \"zero\": 0,
        \"one\": 1,
        \"space\": \" \",
        \"quote\": \"\\\"\",
        \"backslash\": \"\\\\\",
        \"controls\": \"\\b\\f\\n\\r\\t\",
        \"slash\": \"/ & \\/\",
        \"alpha\": \"abcdefghijklmnopqrstuvwyz\",
        \"ALPHA\": \"ABCDEFGHIJKLMNOPQRSTUVWYZ\",
        \"digit\": \"0123456789\",
        \"0123456789\": \"digit\",
        \"special\": \"`1~!@#$%^&*()_+-={':[,]}|;.</>?\",
        \"hex\": \"\\u0123\\u4567\\u89AB\\uCDEF\\uabcd\\uef4A\",
        \"true\": true,
        \"false\": false,
        \"null\": null,
        \"array\":[  ],
        \"object\":{  },
        \"address\": \"50 St. James Street\",
        \"url\": \"http://www.JSON.org/\",
        \"comment\": \"// /* <!-- --\",
        \"# -- --> */\": \" \",
        \" s p a c e d \" :[1,2 , 3
,
4 , 5        ,          6           ,7        ],\"compact\":[1,2,3,4,5,6,7],
        \"jsontext\": \"{\\\"object with 1 member\\\":[\\\"array with 1 element\\\"]}\",
        \"quotes\": \"&#34; \\u0022 %22 0x22 034 &#x22;\",
        \"\\/\\\\\\\"\\uCAFE\\uBABE\\uAB98\\uFCDE\\ubcda\\uef4A\\b\\f\\n\\r\\t`1~!@#$%^&*()_+-=[]{}|;:',./<>?\"
: \"A key can be any string\"
    },
    0.5 ,98.6
,
99.44
,
1066,
1e1,
0.1e1,
1e-1,
1e00,2e+00,2e-00
,\"rosebud\"]"))
