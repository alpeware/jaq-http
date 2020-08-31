(ns jaq.http.xrf.css
  "CSS rules.

  Allows specifying CSS rules as vectors and maps.

  - https://www.w3.org/Style/CSS/specs.en.html
  - https://developer.mozilla.org/en-US/docs/Web/CSS/Syntax
  "
  (:require
   [clojure.string :as string]))

#_(
   *e
   (in-ns 'jaq.http.xrf.css)
   (in-ns 'clojure.core)
   )

(def ^:private space " ")
(def ^:private comma ", ")
(def ^:private colon ": ")
(def ^:private semicolon ";")
(def ^:private l-brace " {")
(def ^:private r-brace "}")

(defn transform [e]
  (cond
    (and (keyword? e) (namespace e))
    (str ":" (name e))

    (keyword? e)
    (name e)

    (and (vector? e) (->> (last e) (vector?)))
    (->> (last e) (map transform) (interpose (first e)) (apply str))

    (vector? e)
    (->> e (map transform) (interpose space) (apply str))

    :default
    (str e)))

#_(
   (namespace ::foo)
   )

(defn css [& rules]
  (->> rules
       (map (fn [e]
              (let [selectors (->> e
                                   (butlast)
                                   (map transform)
                                   (string/join comma))
                    block (->> e
                               (last)
                               (map (fn [[k v]]
                                      [(name k) colon (transform v) semicolon]))
                               (map (fn [g] (apply str g))))]
                (str selectors l-brace (apply str block) r-brace))))
       (interpose space)
       (apply str)))

#_(
   (css [::root {:--font-family ["," ["Helvetica" "Arial"]]
                 :box-shadow [:inset :0.25rem "0.25rem" "#ddd"]}])

   )
#_(
   (let [rules [[:input :.cta {:foo :bar :baz :bazz}]
                [:input :.cta {:foo :bar :baz :bazz}]
                [::root {:--foo 123}]]]
     (->> rules
          (map (fn [e]
                 (let [selectors (->> e
                                      (butlast)
                                      (map transform)
                                      (string/join comma))
                       block (->> e
                                  (last)
                                  (map (fn [[k v]]
                                         [(name k) colon (transform v) semicolon]))
                                  (map (fn [g] (apply str g))))]
                   (str selectors l-brace (apply str block) r-brace))))
          (interpose space)
          (apply str)))
   )


#_(

   (name :button:focus)
   (name :.cta)
   (name :--foo)
   (name :#fafafa)
   (#_garden.core/css
    css
    [":root" {"--font-plain" "Helvetica Neue,Helvetica,Arial,sans-serif"
              "--font-special" "Barlow Condensed,Helvetica,sans-serif"
              "--font-mono" "Menlo,Courier,Courier New,Andale Mono,monospace"
              "--color-dark" "#050505"
              "--color-darkish" "#404040"
              "--color-light" "#fafafa"
              "--color-lightish" "#e6e6e6"
              "--color-mid" "grey"
              "--ratio" 1.4
              "--s0" "1rem"
              "--measure" "65ch"
              "--border-thin" "var(--s-5)"
              "--border-thick" "var(--s-2)"
              :line-height "var(ratio)"
              :font-size "calc(.333vw + 1em)"
              :font-family "var(--font-plain)"
              :background-color "var(--color-light)"
              :color "var(--color-dark)"}]
    [:input {:width "100%"
             :border-width "var(--border-thin)"
             :padding "var(--s-1)"
             :box-shadow "inset 0.25rem 0.25rem #ddd"}]
    [:input:focus {:outline-offset 0}]
    [:button :.cta {:font-size "inherit"}])

   *e

   )
