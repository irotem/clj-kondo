(ns clj-kondo.impl.analyzer.security
  {:no-doc true}
  (:require
    [clj-kondo.impl.analyzer.common :refer [analyze-expression**
                                            analyze-like-let]]
    [clj-kondo.impl.findings :as findings]
    [clj-kondo.impl.utils :as utils :refer [node->line]])
  (:import [clj_kondo.impl.rewrite_clj.node.string StringNode]))

(defn foundVulnerability [ctx expr m category message]
  (findings/reg-finding!
    ctx
    (node->line (:filename ctx)
                expr
                :error
                :security-high
                {
                 :info message
                 :rule (name category)
                 }))
  )

(defn hasVariables [coll]
  (not (every? (fn [item]
                 (instance? StringNode item)
                 ) coll))
  )

(defn analyze
  "TODO: add security info"
  [ctx
   expr
   {:keys [ns name interop?] :as m}]
  (let []
    (if interop?
      (case (str (first (:children expr)))
        "RT/readString"
        (when (hasVariables (next (:children expr)))
          (foundVulnerability ctx expr m :READ-STRING "Found Read-String in code"))
        )
      (case [ns name]
        ([clojure.core read-string]
         [clojure.core read])
        (when (hasVariables (next (:children expr)))
          (foundVulnerability ctx expr m :READ-STRING "Found Read-String in code"))
        ""
        )))
  )
