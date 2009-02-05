;;; Copyright (c) 2008, xristos@suspicious.org.  All rights reserved.

;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:

;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.

;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.

;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

;;;;
;;;; pcap.lisp 
;;;; CFFI binding to libpcap
;;;;
;;;; Contains bindings to every function available
;;;; in libpcap. Direct usage of these functions is not recommended.
;;;; 

(in-package :plokami)

(defconstant +error-buffer-size+ 256) ; PCAP_ERRBUF_SIZE
(defconstant +PCAP_IF_LOOPBACK+  1)

(defconstant +DLT_NULL+ 0)
(defconstant +DLT_EN10MB+ 1)
(defconstant +DLT_SLIP+ 8)
(defconstant +DLT_PPP+ 9)
(defconstant +DLT_PPP_BSDOS1+ 14)
(defconstant +DLT_PPP_BSDOS2+ 16)
(defconstant +DLT_PPP_SERIAL+ 50)
(defconstant +DLT_PPP_ETHER+ 51)
(defconstant +DLT_PPP_PPPD+ 166)

;; Supported datalink types
(defparameter *supported-datalinks*
  `(("NULL" . ,+DLT_NULL+)
    ("EN10MB" . ,+DLT_EN10MB+)
    ("SLIP" . ,+DLT_SLIP+)
    ("PPP" . ,+DLT_PPP+)
    ("PPP-BSDOS" . ,+DLT_PPP_BSDOS1+)
    ("PPP-BSDOS" . ,+DLT_PPP_BSDOS2+)
    ("PPP-SERIAL" . ,+DLT_PPP_SERIAL+)
    ("PPP-ETHER" . ,+DLT_PPP_ETHER+)
    ("PPP-PPPD" . ,+DLT_PPP_PPPD+)))


(defparameter *pcap-version* nil
  "Version of native libpcap library.")


(define-foreign-library libpcap
  (:win32 (:default "wpcap"))
  (:unix (:default "libpcap"))) ; Might need fixing with new CFFI

(use-foreign-library libpcap)

;;; ------------------------------

(defcenum pcap_direction_t
  :PCAP_D_INOUT
  :PCAP_D_IN
  :PCAP_D_OUT)

(defcstruct timeval
  "Timeval structure."
  (tv_sec :long)
  (tv_usec :long))

(defcstruct pcap_pkthdr
  "Packet header structure."
  (ts timeval)
  (caplen :uint32)
  (len :uint32))

(defcstruct pcap_if_t
  "Pcap interface structure."
  (next :pointer)                     ; pcap_if_t *
  (name :string)                      
  (description :string)
  (addresses :pointer)                 ; pcap_addr_t *
  (flags :uint32))

(defcstruct pcap_addr_t
  "Pcap interface network address structure."
  (next :pointer)                     ; pcap_addr_t *
  (addr :pointer)                     ; sockaddr *
  (netmask :pointer)                  ; sockaddr *
  (broadaddr :pointer)                ; sockaddr *
  (dstaddr :pointer))                 ; sockaddr *


(defcstruct sockaddr
  "BSD SOCKADDR structure."
  (sa_len :uint8)
  (sa_family :uint8)
  (sa_data :char))


;; Missing field for win32
(defcstruct pcap_stat
  "Pcap packet capture statistics structure."
  (ps_recv :uint)
  (ps_drop :uint)
  (ps_ifdrop :uint))


(defcstruct bpf_program
  "Berkeley Packet Filter program structure."
  (bf_len :uint)
  (bf_insns :pointer))                ; bpf_insn *

(defcstruct bpf_insn
  "Berkeley Packet Filter instruction strucure."
  (code :ushort)
  (jt :uchar)
  (jf :uchar)
  (k :int32))

;;; ------------------------------
;;; Functions

#+:sbcl
(defcfun ("memcpy" %memcpy) :pointer
  (dst :pointer)
  (src :pointer)
  (len :long))

(defcfun ("inet_ntop" %inet-ntop) :int
  (af :int)
  (src :pointer)
  (dst :pointer)
  (size :uint32))

(defcfun ("link_ntoa" %link-ntoa) :string
  (sdl :pointer))

(defcfun ("gettimeofday" %gettimeofday) :int
  (tp :pointer)
  (tzp :pointer))


;;; Pcap specific

(defcfun ("pcap_open_live" %pcap-open-live) :pointer ; pcap_t *
  (device :string)
  (snaplen :int)
  (promisc :boolean)
  (to_ms :int)
  (errbuf :pointer))                  ; char * 

(defcfun ("pcap_open_dead" %pcap-open-dead) :pointer ; pcap_t *
  (linktype :int)
  (snaplen :int))

(defcfun ("pcap_open_offline" %pcap-open-offline) :pointer ; pcap_t *
  (filename :string)
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_dump_open" %pcap-dump-open) :pointer ; pcap_dumper_t *
  (pcap_t :pointer)
  (fname :string))

(defcfun ("pcap_setnonblock" %pcap-setnonblock) :int
  (pcap_t :pointer)                   ; pcap_t *
  (nonblock :boolean)
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_getnonblock" %pcap-getnonblock) :int
  (pcap_t :pointer)                   ; pcap_t *
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_findalldevs" %pcap-findalldevs) :int
  (alldevsp :pointer)                 ; pcap_if_t *
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_freealldevs" %pcap-freealldevs) :void
  (alldevs :pointer))                 ; pcap_if_t *


(defcfun ("pcap_lookupdev" %pcap-lookupdev) :string
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_lookupnet" %pcap-lookupnet) :int
  (device :string)
  (netp :pointer)                     ; uint32 *
  (maskp :pointer)                    ; uint32 *
  (errbuf :pointer))                  ; char *

(defcfun ("pcap_dispatch" %pcap-dispatch) :int
  (pcap_t :pointer)                   ; pcap_t *
  (cnt :int)
  ; void (*pcap_handler) (u_char *user,const struct pcap_pkthdr *h, const
  ;                       u_char *bytes
  (callback :pointer) 
  (user :pointer))                    ; uchar *, gets passed to handler

(defcfun ("pcap_loop" %pcap-loop) :int
  (pcap_t :pointer)                   ; pcap_t *
  (cnt :int)
  ; void (*pcap_handler) (u_char *user,const struct pcap_pkthdr *h, const
  ;                       u_char *bytes
  (callback :pointer)
  (user :pointer))                    ; uchar *, gets passed to handler


(defcfun ("pcap_dump" %pcap-dump) :void
  (user :pointer)                     ; uchar *
  (header :pointer)                   ; pcap_pkthdr *
  (sp :pointer))                      ; uchar *

(defcfun ("pcap_compile" %pcap-compile) :int
  (pcap_t :pointer)                   ; pcap_t *
  (fp :pointer)                       ; bpf_program *
  (str :string)
  (optimize :int)
  (netmask :uint32))

(defcfun ("pcap_setfilter" %pcap-setfilter) :int
  (pcap_t :pointer)                   ; pcap_t *
  (fp :pointer))                      ; bpf_program * 

(defcfun ("pcap_freecode" %pcap-freecode) :void
  (fp :pointer))                      ; bpf_program *

(defcfun ("pcap_setdirection" %pcap-setdirection) :int
  (pcap_t :pointer)                   ; pcap_t *
  (d pcap_direction_t))

(defcfun ("pcap_next" %pcap-next) :pointer
  (pcap_t :pointer)                   ; pcap_t *
  (header :pointer))                  ; pcap_pkthdr *

(defcfun ("pcap_next_ex" %pcap-next-ex) :int
  (pcap_t :pointer)                   ; pcap_t *
  (headerp :pointer)                  ; pcap_pkthdr **
  (datap :pointer))                   ; uchar **

(defcfun ("pcap_breakloop" %pcap-breakloop) :void
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_inject" %pcap-inject) :int
  (pcap_t :pointer)                   ; pcap_t *
  (buf :pointer)                      ; const void *
  (size :int))

(defcfun ("pcap_sendpacket" %pcap-sendpacket) :int
  (pcap_t :pointer)                   ; pcap_t *
  (buf :pointer)
  (size :int))

(defcfun ("pcap_datalink" %pcap-datalink) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_list_datalinks" %pcap-list-datalinks) :int
  (pcap_t :pointer)                   ; pcap_t *
  (dlt_buf :pointer))                 ; int **

(defcfun ("pcap_set_datalink" %pcap-set-datalink) :int
  (pcap_t :pointer)                   ; pcap_t *
  (dlt :int))

(defcfun ("pcap_datalink_name_to_val" %pcap-datalink-name-to-val) :int
  (name :string))

(defcfun ("pcap_datalink_val_to_name" %pcap-datalink-val-to-name) :string
  (dlt :int))

(defcfun ("pcap_datalink_val_to_description" %pcap-datalink-val-to-description)
    :string
  (dlt :int))

(defcfun ("pcap_snapshot" %pcap-snapshot) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_is_swapped" %pcap-is-swapped) :boolean
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_major_version" %pcap-major-version) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_minor_version" %pcap-minor-version) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_stats" %pcap-stats) :int
  (pcap_t :pointer)                   ; pcap_t *
  (ps :pointer))

(defcfun ("pcap_fileno" %pcap-fileno) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_get_selectable_fd" %pcap-get-selectable-fd) :int
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_perror" %pcap-perror) :void
  (pcap_t :pointer)                   ; pcap_t *
  (prefix :string))

(defcfun ("pcap_geterr" %pcap-geterr) :string
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_strerror" %pcap-strerror) :string
  (error :int))
  
(defcfun ("pcap_lib_version" %pcap-lib-version) :string)

(defcfun ("pcap_close" %pcap-close) :void
  (pcap_t :pointer))                  ; pcap_t *

(defcfun ("pcap_dump_flush" %pcap-dump-flush) :int
  (dumper :pointer))                  ; pcap_dumper_t *

(defcfun ("pcap_dump_ftell" %pcap-dump-ftell) :long
  (dumper :pointer))                  ; pcap_dumper_t *

(defcfun ("pcap_dump_close" %pcap-dump-close) :void
  (dumper :pointer))                  ; pcap_dumper_t *


(setf *pcap-version* (%pcap-lib-version))




