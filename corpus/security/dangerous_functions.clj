(ns security.dangerous-functions
     (:import (clojure.lang LispReader RT)))

(read-string (str "x" "xxx" "aaa"))
(RT/readString (str "x"))
(read-string "static-var") ;; <- should not be reported
