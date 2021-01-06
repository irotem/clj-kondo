(ns clj-kondo.security-test
  (:require
    [clj-kondo.test-utils :refer [assert-submaps lint!]]
    [clojure.java.io :as io]
    [clojure.test :refer [deftest is]]
    [missing.test.assertions]))

(def base-config
  '{:linters {:unused-binding               {:level :off}
              :unresolved-symbol            {:level :off}
              :refer-all                    {:level :off}
              :type-mismatch                {:level :off}
              :unsorted-required-namespaces {:level :off}
              :shadowed-var                 {:level :off}
              :unused-import                {:level :off}
              :security-high                {:level :error}
              :security-low                 {:level :warning}
              }
    }
  )

(deftest security-test
  (let [results (lint! (io/file "corpus" "security" "dangerous_functions.clj") base-config)]

    (assert-submaps
      '({:file "corpus/security/dangerous_functions.clj", :row 4, :col 1, :level :error,
         :message "{:info \"Found Read-String in code\", :rule \"READ-STRING\"}"}

        {:file "corpus/security/dangerous_functions.clj", :row 5, :col 1, :level :error,
         :message "{:info \"Found Read-String in code\", :rule \"READ-STRING\"}"})

      results)
    )
  )
