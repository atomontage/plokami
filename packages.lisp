;; Copyright (c) 2008, xristos@sdf.lonestar.org.  All rights reserved.

;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:

;;   * Redistributions of source code must retain the above copyright
;;     notice, this list of conditions and the following disclaimer.

;;   * Redistributions in binary form must reproduce the above
;;     copyright notice, this list of conditions and the following
;;     disclaimer in the documentation and/or other materials
;;     provided with the distribution.

;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(in-package :cl-user)

(defpackage :plokami
  (:use :cl :cffi)
  (:export :*pcap-version*             ; [dynamic-var] library version string
           :make-pcap-live             ; [function:constructor]
           :make-pcap-reader           ; [function:constructor]
           :make-pcap-writer           ; [function:constructor]
           :pcap-live-interface        ; [reader]
           :pcap-live-promisc-p        ; [reader]
           :pcap-live-timeout          ; [reader]
           :pcap-live-descriptor       ; [reader]
           :pcap-live-alive-p          ; [reader]
           :pcap-live-datalink         ; [reader]
           :pcap-live-snaplen          ; [reader]
           :pcap-reader-file           ; [reader]
           :pcap-reader-swapped-p      ; [reader]
           :pcap-reader-major          ; [reader]
           :pcap-reader-minor          ; [reader]
           :pcap-reader-alive-p        ; [reader]
           :pcap-reader-datalink       ; [reader]
           :pcap-reader-snaplen        ; [reader]
           :pcap-writer-file           ; [reader]
           :pcap-writer-datalink       ; [reader]
           :pcap-writer-alive-p        ; [reader]
           :pcap-writer-snaplen        ; [reader]
           :plokami-error-text         ; [condition reader]
           :plokami-error              ; [condition]
           :network-interface-error    ; [condition]
           :packet-filter-error        ; [condition]
           :capture-file-read-error    ; [condition]
           :capture-file-write-error   ; [condition]
           :packet-capture-error       ; [condition]
           :packet-inject-error        ; [condition]
           :block-mode-error           ; [condition]
           :continue-block-mode        ; [restart]
           :continue-no-filter         ; [restart]
           :stop                       ; [generic function]
           :capture                    ; [generic function]
           :stats                      ; [generic function]
           :inject                     ; [generic function]
           :dump                       ; [generic function]
           :set-non-block              ; [generic function]
           :set-filter                 ; [generic function]
           :find-all-devs              ; [function]
           :with-pcap-interface        ; [macro]
           :with-pcap-reader           ; [macro]
           :with-pcap-writer))         ; [macro]


