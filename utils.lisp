;;;;
;;;; utils.lisp
;;;; Some utility functions and callback generators
;;;;

(in-package :plokami)

(defmacro with-capture-callback (&body body)
  "Create an anonymous function that accepts `SEC', `USEC', `CAPLEN', `LEN'
and `BUFFER' as arguments (in that order) and executes forms in `BODY'."
  `(lambda (sec usec caplen len buffer)
     ,@body))