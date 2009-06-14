;;; Copyright (c) 2008 xristos@suspicious.org.  All rights reserved.

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
;;;; plokami.lisp
;;;; Lispy interface to libpcap
;;;;
;;;;
;;;; DONE: BPF, inject, dumpfile input, dumpfile output, live capture, nbio.
;;;; TODO-ClozureCL: Optimize buffer copying.
;;;;
;;;; When using multiple pcap instances to capture packets at the same time
;;;; on different threads, access to *callbacks* and *concurrentpcap*
;;;; should be synchronized according to implementation. This is currently
;;;; implemented only for SBCL and CCL.
;;;;
;;;; Also, thread safety of libpcap itself is not clearly defined so proceed
;;;; with caution. Multithreading seems to work fine with the exception of
;;;; pcap_compile which uses global data structures and should only be called
;;;; in a synchronized way. This is done in set-filter for SBCL and CCL using
;;;; *compile-mutex*.
;;;;
;;;; Finally, read timeouts on live packet capture are not supported on every
;;;; platform. This is a libpcap/operating system issue. If in doubt, read
;;;; the platform specific libpcap documentation and experiment.
;;;; You should not depend on read timeouts firing (ie. capture returning
;;;; within timeout) if your code needs to run on multiple operating systems.
;;;;
;;;; The best way to make sure that capture does not wait forever, is to use
;;;; non-blocking mode in combination with your own event notification scheme
;;;; (select/epoll/kqueue etc). This is also the preferred way to capture
;;;; packets from multiple pcap instances, threads should be considered as
;;;; a last resort.
;;;;
;;;; How to use:
;;;;
;;;; 1) Invoke constructors: make-pcap-live, make-pcap-reader, make-pcap-writer
;;;;
;;;; 2) Invoke methods specialized on these three classes mainly
;;;;    capture, dump, set-nonblock, set-filter, stats
;;;;
;;;; 3) Invoke stop when finished
;;;;
;;;; OR use convenience macros (with-pcap-interface, with-pcap-reader,
;;;;                            with-pcap-writer) that wrap most of the above

;;;; Examples:
;;;;
;;;; Read/process/dump packets in realtime, do not block.
;;;; Interrupt to cleanup and exit.

#|
(with-pcap-interface (pcap "en0" :promisc t :snaplen 1500 :nbio t)
  (with-pcap-writer (writer "session.pcap" :snaplen 1500 :datalink
                            (pcap-live-datalink pcap))
    (loop
       (capture pcap -1
                #'(lambda (sec usec caplen len buffer)
                    ;; sec and usec at the time of the capture
                    ;; caplen -> size of captured packet
                    ;; len -> original size of packet
                    ;; (may be > caplen, depends on snaplen)
                    ;; buffer -> byte vector with packet contents
                    (dump writer buffer :length caplen
                          :origlength len :sec sec :usec usec)
                    (format t
                            "Captured packet, size: ~A original: ~A~%"
                            caplen len)))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
       ;; Sleep will have to do for this example
       (sleep 0.01))))
|#



(in-package :plokami)

;;; Globals

(defvar *callbacks*
  #+sb-thread (make-hash-table :synchronized t)
  #+openmcl-native-threads (make-hash-table :shared t)
  #-(or sb-thread openmcl-native-threads) (make-hash-table)
  )

(defvar *concurrentpcap* 1)

(defvar *concurrentpcap-mutex*
  #+sb-thread (sb-thread:make-mutex :name "*concurrent-pcap* lock")
  #+openmcl-native-threads (ccl:make-lock)
  #-(or :sb-thread :openmcl-native-threads)
  (progn (warn "Locking not done on this implementation. Avoid threads.")
         nil)
  )

;; Mutex for pcap_compile which is not thread safe
(defvar *compile-mutex*
  #+sb-thread (sb-thread:make-mutex :name "*compile-mutex* lock")
  #+openmcl-native-threads (ccl:make-lock)
  #-(or :sb-thread :openmcl-native-threads)
  (progn (warn "Locking not done on this implementation. Avoid threads.")
         nil)
  )


;;; ------------------------------
;;; Internal Functions


(defun make-error-buffer ()
  "Allocate and return foreign char array to hold error string."
  (foreign-alloc :char :count +error-buffer-size+ :initial-element 0))

(defun clear-error-buffer (foreign-buffer)
  "Set `FOREIGN-BUFFER' to the empty string."
  (setf (mem-aref foreign-buffer :char) 0))

(defun error-buffer-to-lisp (foreign-buffer)
  "Return `FOREIGN-BUFFER' as a lisp string."
  (foreign-string-to-lisp foreign-buffer))

(defun free-error-buffer (foreign-buffer)
  "Free memory held by `FOREIGN-BUFFER'."
  (foreign-free foreign-buffer))

(defmacro with-error-buffer ((error-buffer) &body body)
  `(let ((,error-buffer (make-error-buffer)))
     (unwind-protect
          (progn ,@body)
       (free-error-buffer ,error-buffer))))

(defun get-time-of-day ()
  "Return `NIL' if gettimeofday fails else seconds, microseconds as multiple
values."
  (with-foreign-object (tv 'timeval)
    (when (= -1 (%gettimeofday tv (null-pointer)))
      (return-from get-time-of-day))
    (with-foreign-slots ((tv_sec tv_usec) tv timeval)
      (values tv_sec tv_usec))))

;;; This is passed to the foreign side and when called, invokes the lisp
;;; packet handler that the user defined (slot /handler/ in pcap-process-mixin)
(defcallback pcap-handler :void
    ((user :pointer) (pkthdr :pointer)
     (bytes :pointer))
  (let* ((key (mem-aref user :int))
         (pcap (gethash key *callbacks*)))
    (with-foreign-slots ((ts caplen len) pkthdr pcap_pkthdr)
      (with-foreign-slots ((tv_sec tv_usec) ts timeval)
        (with-slots (buffer handler) pcap
          ;; Copy packet data from C to lisp
          #+:sbcl
          (sb-sys:with-pinned-objects (buffer)
            (%memcpy (sb-sys:vector-sap buffer) bytes caplen))
          #-:sbcl
          (loop :for i :from 0 :to (- caplen 1) :do
               (setf (aref buffer i)
                     (mem-aref bytes :uint8 i)))
          ;; Call lisp packet handler
          (funcall handler tv_sec tv_usec
                   caplen len buffer))))))


;;; ------------------------------
;;; Classes


(defclass pcap-mixin ()
  ((pcap_t
    :initform nil
    :documentation "Foreign pointer to pcap structure.")
   (datalink
    :initform nil
    :documentation "Datalink protocol for this device.")
   (snaplen
    :initform 68 ; Same as tcpdump, enough for headers
    :documentation "How many bytes to capture per packet received.")
   (live
    :initform nil
    :documentation "Packet capture object is live."))
  (:documentation
   "Internal class used as a mixin for all classes with pcap functionality."))


(defclass pcap-process-mixin ()
  ((buffer
    :initform nil
    :documentation "Packet buffer to hold captured packets.")
   (handler
    :initform nil
    :documentation "Lisp packet handler for capture. Invoked by callback.")
   (hashkey
    :initform nil
    :documentation "Hashtable key for this instance.")
   (hashkey-pointer
    :initform nil
    :documentation "Foreign pointer to hashkey, passed in callback."))
  (:documentation
   "Internal class, mixed in packet processing (PCAP-LIVE, PCAP-READER)."))


(defclass pcap-live (pcap-process-mixin pcap-mixin)
  ((interface
    :initarg :if
    :reader pcap-live-interface
    :initform nil
    :documentation "Interface to capture packets from.")
   (promisc
    :initarg :promisc
    :reader pcap-live-promisc
    :initform nil
    :documentation "True if capturing in promiscuous mode.")
   (non-block
    :initarg :nbio
    :initform nil
    :documentation "True if pcap descriptor is in non-blocking mode.")
   (timeout
    :initarg :timeout
    :reader pcap-live-timeout
    :initform 100
    :documentation "Read timeout in milliseconds. 0 will wait forever.
Only works in blocking mode/platforms that support it. No guarantee of
returning within timeout.")
   (descriptor
    :reader pcap-live-descriptor
    :initform nil
    :documentation "File descriptor that can be used with epoll/kqueue/select.")
   ;; Provide reader for inherited slots
   (live :reader pcap-live-alive)
   (datalink :reader pcap-live-datalink)
   (snaplen :initarg :snaplen :reader pcap-live-snaplen))
  (:documentation
   "Class for live packet capture."))


(defclass pcap-reader (pcap-process-mixin pcap-mixin)
  ((file
    :initarg :file
    :reader pcap-reader-file
    :initform (error "Must supply filename to read packets from.")
    :documentation "File to read packets from.")
   (swapped
    :reader pcap-reader-swapped
    :initform nil
    :documentation "Savefile uses different byte order from host system.")
   (major
    :reader pcap-reader-major
    :initform nil
    :documentation "Major version of savefile.")
   (minor
    :reader pcap-reader-minor
    :initform nil
    :documentation "Minor version of savefile.")
   ;; Provide reader for inherited slots
   (live :reader pcap-reader-alive)
   (datalink :reader pcap-reader-datalink)
   (snaplen :initarg :snaplen :reader pcap-reader-snaplen))
  (:documentation
   "Class for reading packets from a dumpfile."))


(defclass pcap-writer (pcap-mixin)
  ((file
    :initarg :file
    :reader pcap-writer-file
    :initform (error "Must supply file to write packets to.")
    :documentation "File to write packets to.")
   (dumper :initform nil
           :documentation "Foreign packet dumper object.")
   (datalink :initarg :datalink :initform "EN10MB" :reader pcap-writer-datalink)
   (live :reader pcap-writer-alive)
   (snaplen :initarg :snaplen :reader pcap-writer-snaplen))
  (:documentation
   "Class for writing packets to a dumpfile."))

;;; ------------------------------
;;; Constructors

(defun make-pcap-live (interface &key promisc nbio (timeout 100) (snaplen 68))
  "Creates and returns a `PCAP-LIVE' instance that is used for live packet
capture from a network interface.

`INTERFACE' is a string that defines the network interface to use for capture.
`PROMISC' should be T for promiscuous mode, `NIL' otherwise.
`NBIO' should be T when non-blocking operation is required. `NIL' otherwise
(default). `TIMEOUT' should hold read timeout in milliseconds.
0 will wait forever. Only used when in blocking mode and only in platforms
that support it. No guarantee of actually returning within `TIMEOUT' is made.
Use non-blocking mode if that is not adequate. `SNAPLEN' should contain the
number of bytes captured per packet. Default is 68 which should be enough
for headers."
  (make-instance 'pcap-live :if interface  :promisc promisc :nbio nbio
                 :timeout timeout :snaplen snaplen))


(defun make-pcap-reader (file &key (snaplen 68))
  "Creates and returns a `PCAP-READER' instance that is used for reading
packets from a pcap dumpfile.

`FILE' is the filename to open and read packets from. `SNAPLEN' should contain
the number of bytes read per packet captured. Default is 68 which should
be enough for headers."
  (make-instance 'pcap-reader :file file :snaplen snaplen))


(defun make-pcap-writer (file &key (datalink "EN10MB") (snaplen 68))
  "Creates and returns a `PCAP-WRITER' instance that is used to write packets
to a pcap dumpfile.

`FILE' is the filename to open and write packets to. `DATALINK' should contain
a string that represents the datalink protocol of the network interface used
to capture the packets. Default is Ethernet. `SNAPLEN' should contain the
number of bytes read per packet captured and should be the same as the one
used when capturing/reading the packets."
  (make-instance 'pcap-writer :file file :datalink datalink :snaplen snaplen))

;;; ------------------------------
;;; Conditions

(define-condition plokami-error (error) ()
  (:documentation "Generic condition for this package."))

(define-condition network-interface-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled on all network interface errors."))

(define-condition capture-file-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled on all pcap file errors."))

(define-condition packet-filter-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled when a berkeley packet filter could not be
established."))

(define-condition packet-capture-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled on error during live packet capture."))


(define-condition packet-inject-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled on errors during packet injection."))


(define-condition block-mode-error (plokami-error)
  ((text :initarg :text :reader text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition))))
  (:documentation "Signaled on error when changing blocking mode."))


;;; ------------------------------
;;; Generic functions & methods

(defgeneric stop (pcap-mixin)
  (:method-combination progn)
  (:documentation "Deallocates resources for `PCAP-LIVE', `PCAP-READER',
`PCAP-WRITER' instance."))

(defgeneric capture (pcap-process-mixin packets handler)
  (:documentation "Only works for `PCAP-LIVE' or `PCAP-READER' instances.
Captures and processes maximum number of `PACKETS'. Minimum is
zero. Return 0 when no packets available (for dumpfiles: when end of file)
otherwise return number of packets processed which can be
fewer than the maximum given in `PACKETS' (due to pcap buffer).

A count of -1 in `PACKETS' processes all the packets received so far when live
capturing, or all the packets in a file when reading a pcap dumpfile.

Handler must be a user defined function that accepts five arguments and will
get called once for every packet received. The values passed are `SEC', `USEC',
`CAPLEN', `LEN' and `BUFFER'. `SEC' and `USEC' correspond to
seconds/microseconds since the UNIX epoch (timeval structure in C) at the time
of capture. `CAPLEN' corresponds to the number of bytes captured. `LEN'
corresponds to the number of bytes originally present in the packet but not
necessarilly captured. `BUFFER' is a statically allocated byte vector with the
contents of the captured packet. This means that successive calls of the
packet handler will overwrite its contents and if packet persistence is
required, contents of `BUFFER' should be copied somewhere else from within
`HANDLER'.

If an error occurs, `PACKET-CAPTURE-ERROR' is signalled for live
interfaces and `CAPTURE-FILE-ERROR' for pcap dumpfiles. For more details
on callback handling, see CFFI callback `PCAP-HANDLER'."))


(defgeneric set-nonblock (pcap-live block-mode)
  (:documentation "Sets non-blocking mode if `BLOCK-MODE' is `T', blocking
mode if `NIL'. `BLOCK-MODE-ERROR' is signalled on failure and a restart,
`CONTINUE-BLOCK-MODE' is installed, that can be invoked to continue."))

(defgeneric stats (pcap-live)
  (:documentation "Returns packet capture statistics from the start of the run
to the time of the call for live interface capture only. Statistics are
returned as multiple values and correspond to packets received,
packets dropped and packets dropped by interface (in this order).
`NETWORK-INTERFACE-ERROR' is signalled on failure."))


(defgeneric inject (pcap-live buffer &key length)
  (:documentation "Injects `LENGTH' bytes to a live pcap interface
(size of `BUFFER' if ommitted). `PACKET-INJECT-ERROR' is signalled on
failure."))


(defgeneric set-filter (pcap-process-mixin string)
  (:documentation "Sets a packet filter on a `PCAP-LIVE' or `PCAP-READER'
instance. The filter should be given as a BPF expression in `STRING'.
`PACKET-FILTER-ERROR' is signalled on failure. A restart, `CONTINUE-NO-FILTER'
is installed that can be invoked to continue on error."))


(defgeneric dump (pcap-writer data &key length origlength sec usec)
  (:documentation "Writes contents of byte vector `DATA' to `PCAP-WRITER'
instance (which corresponds to a pcap dumpfile). `LENGTH' is the number of bytes
to write and is set to the size of `DATA' when omitted. `ORIGLENGTH' should be
set to the number of bytes originally present in the packet and is set to
`LENGTH' when omitted. `SEC' and `USEC' should be set to seconds/microseconds
since the UNIX epoch at the time of capture (timeval structure in C)
and are set to current values when omitted. `CAPTURE-FILE-ERROR' is
signalled on errors."))


(defmethod stop progn ((cap pcap-mixin))
  (with-slots (pcap_t live) cap
    (when live
      (%pcap-close pcap_t)
      (setf live nil))))

(defmethod stop progn ((cap pcap-process-mixin))
  (with-slots (live hashkey hashkey-pointer) cap
    (when live
      #+sb-thread
      (sb-thread:with-mutex (*concurrentpcap-mutex*)
          (remhash hashkey *callbacks*))
      #+openmcl-native-threads
      (ccl:with-lock-grabbed (*concurrentpcap-mutex*)
        (remhash hashkey *callbacks*))
      #-(or sb-thread openmcl-native-threads)
      (remhash hashkey *callbacks*)
      (foreign-free hashkey-pointer))))

(defmethod stop progn ((cap pcap-writer))
  (with-slots (live dumper pcap_t) cap
    (when live
      ;; FIXME: Need to insert error checking here
      (%pcap-dump-flush dumper)
      (%pcap-dump-close dumper))))



;; Signals network-interface-error
(defmethod initialize-instance :after ((cap pcap-live) &key)
  (with-slots (pcap_t interface snaplen promisc timeout datalink buffer handler
                      hashkey hashkey-pointer live non-block descriptor)
      cap
    (with-error-buffer (eb)
      ;; No interface given, call lookupdev to get one
      (when (null interface)
        (let ((res (%pcap-lookupdev eb)))
          (when (null res)
            (error 'network-interface-error :text
                   (error-buffer-to-lisp eb)))
          (setf interface res)))
      (clear-error-buffer eb)
      ;; Open interface for capture
      (let* ((res (%pcap-open-live interface snaplen promisc timeout eb))
             (ebtext (error-buffer-to-lisp eb)))
        (when (null-pointer-p res)
          (error 'network-interface-error :text ebtext))
        (when (not (= 0 (length ebtext)))
          (warn ebtext))
        (setf pcap_t res)
        ;; Supported datalink test
        (let ((dlink (rassoc (%pcap-datalink pcap_t) *supported-datalinks*)))
          (when (not dlink)
            (%pcap-close pcap_t)
            (error 'network-interface-error :text
                   (format nil "~A: Unsupported datalink protocol." interface)))
          (setf datalink (car dlink)))
        (setf buffer (make-array snaplen :element-type
                                 '(unsigned-byte 8))
              live t)
        ;; Hash pcap instance for callback discovery
        #+sb-thread
        (sb-thread:with-mutex (*concurrentpcap-mutex*)
          (setf (gethash *concurrentpcap* *callbacks*) cap
                hashkey *concurrentpcap*)
          (incf *concurrentpcap*))
        #+openmcl-native-threads
        (ccl:with-lock-grabbed (*concurrentpcap-mutex*)
          (setf (gethash *concurrentpcap* *callbacks*) cap
                hashkey *concurrentpcap*)
          (incf *concurrentpcap*))
        #-(or sb-thread openmcl-native-threads)
        (progn
          (setf (gethash *concurrentpcap* *callbacks*) cap
              hashkey *concurrentpcap*)
          (incf *concurrentpcap*))
        (setf hashkey-pointer (foreign-alloc :int :initial-element hashkey))
        (when non-block
          (set-nonblock cap t))))))


;; Signals capture-file-error
(defmethod initialize-instance :after ((cap pcap-reader) &key)
  (with-slots (pcap_t file snaplen datalink buffer handler hashkey live
                      swapped major minor hashkey-pointer) cap
    (with-error-buffer (eb)
      (let* ((res (%pcap-open-offline file eb))
             (ebtext (error-buffer-to-lisp eb)))
        (when (null-pointer-p res)
          (error 'capture-file-error :text ebtext))
        (setf pcap_t res)
        ;; Supported datalink test
        (let ((dlink (rassoc (%pcap-datalink pcap_t) *supported-datalinks*)))
          (when (not dlink)
            (%pcap-close pcap_t)
            (error 'capture-file-error :text
                   (format nil "~A: Unsupported datalink protocol." file)))
          ;; Initialize instance slots
          (setf datalink (car dlink)
                snaplen (%pcap-snapshot pcap_t)
                buffer (make-array snaplen :element-type '(unsigned-byte 8))
                swapped (%pcap-is-swapped pcap_t)
                major (%pcap-major-version pcap_t)
                minor (%pcap-minor-version pcap_t)
                live t)
          ;; Hash pcap instance for callback discovery
          #+sb-thread
          (sb-thread:with-mutex (*concurrentpcap-mutex*)
            (setf (gethash *concurrentpcap* *callbacks*) cap
                  hashkey *concurrentpcap*)
            (incf *concurrentpcap*))
          #+openmcl-native-threads
          (ccl:with-lock-grabbed (*concurrentpcap-mutex*)
            (setf (gethash *concurrentpcap* *callbacks*) cap
                  hashkey *concurrentpcap*)
            (incf *concurrentpcap*))
          #-(or sb-thread openmcl-native-threads)
          (progn
            (setf (gethash *concurrentpcap* *callbacks*) cap
                  hashkey *concurrentpcap*)
            (incf *concurrentpcap*))
          (setf hashkey-pointer
                (foreign-alloc :int :initial-element hashkey)))))))

;; Signals capture-file-error
(defmethod initialize-instance :after ((cap pcap-writer) &key)
  (with-slots (pcap_t dumper file datalink live snaplen) cap
    (setf pcap_t (%pcap-open-dead (%pcap-datalink-name-to-val datalink)
                                snaplen))
    (let ((res (%pcap-dump-open pcap_t file)))
      (when (null-pointer-p res)
        (let ((errtext (%pcap-geterr pcap_t)))
          (%pcap-close pcap_t)
          (error 'capture-file-error :text errtext)))
      (setf dumper res
            live t))))


;; Signals packet-capture-error
(defmethod capture ((cap pcap-live) (packets integer) (phandler function))
  (with-slots (pcap_t hashkey handler hashkey-pointer) cap
      (setf handler phandler)
      ;; %pcap-loop and %pcap-next do not work in non-blocking mode
      ;; %pcap-dispatch returns 0 when no packets are avail, -1 on error
      (let ((res (%pcap-dispatch pcap_t packets (callback pcap-handler)
                                 hashkey-pointer)))
        (when (= -1 res)
          (error 'packet-capture-error :text (%pcap-geterr pcap_t)))
        res)))


;; Signals capture-file-error
(defmethod capture ((cap pcap-reader) (packets integer) (phandler function))
  (with-slots (pcap_t hashkey handler hashkey-pointer) cap
    (setf handler phandler)
    (let ((res (%pcap-dispatch pcap_t packets (callback pcap-handler)
                               hashkey-pointer)))
      (when (= -1 res)
        (error 'capture-file-error :text (%pcap-geterr pcap_t)))
      res)))


;; Signals block-mode-error
(defmethod set-nonblock ((cap pcap-live) block-mode)
  (restart-case
      (with-slots (pcap_t non-block descriptor) cap
        (with-error-buffer (eb)
          (when (= -1 (%pcap-setnonblock pcap_t block-mode eb))
            (error 'block-mode-error :text
                   (error-buffer-to-lisp eb))))
        (let ((fd (%pcap-get-selectable-fd pcap_t)))
          (when (= -1 fd)
            (setf fd nil)
            (warn "Non-blocking mode requested, selectable FD not available."))
          (setf non-block block-mode
                descriptor fd)))
    (continue-block-mode () (warn "Error setting non-blocking mode."))))



;; Signals network-interface-error
(defmethod stats ((cap pcap-live))
  (with-slots (pcap_t) cap
    (with-foreign-object (stat 'pcap_stat)
      (when (= -1 (%pcap-stats pcap_t stat))
        (error 'network-interface-error :text
               "Error calculating packet capture statistics."))
      (values (foreign-slot-value stat 'pcap_stat 'ps_recv)
              (foreign-slot-value stat 'pcap_stat 'ps_drop)
              (foreign-slot-value stat 'pcap_stat 'ps_ifdrop)))))


;; Signals packet-inject-error
(defmethod inject ((cap pcap-live) (buffer vector) &key length)
  (when (null length)
    (setf length (length buffer)))
  (with-slots (pcap_t) cap
    (let ((res -1))
      (loop :with foreign-buffer = (foreign-alloc :uint8 :count length)
         :for i :from 0 :below length :do
           (setf (mem-aref foreign-buffer :uint8 i) (aref buffer i))
         :finally (setf res (%pcap-inject pcap_t foreign-buffer length))
           (foreign-free foreign-buffer))
      (when (= -1 res)
        (error 'packet-inject-error :text (%pcap-geterr pcap_t)))
      res)))


;; Signals packet-filter-error
(defmethod set-filter ((cap pcap-live) (filter string))
  (restart-case
      (with-slots (pcap_t interface) cap
        (with-error-buffer (eb)
          (with-foreign-objects ((netp :uint32)
                                 (maskp :uint32)
                                 (fp 'bpf_program))
            (when (= -1 (%pcap-lookupnet interface netp maskp eb))
              (error 'packet-filter-error :text (error-buffer-to-lisp eb)))
            (when (= -1
                     #+sb-thread
                     (sb-thread:with-mutex (*compile-mutex*)
                       (%pcap-compile pcap_t fp filter 1
                                      (mem-aref maskp :uint32)))
                     #+openmcl-native-threads
                     (ccl:with-lock-grabbed (*compile-mutex*)
                       (%pcap-compile pcap_t fp filter 1
                                      (mem-aref maskp :uint32)))
                     #-(or :sb-thread :openmcl-native-threads)
                     (%pcap-compile pcap_t fp filter 1
                                    (mem-aref maskp :uint32))
                     )
              (error 'packet-filter-error :text (%pcap-geterr pcap_t)))
            (when (= -1 (%pcap-setfilter pcap_t fp))
              (%pcap-freecode fp)
              (error 'packet-filter-error :text (%pcap-geterr pcap_t))))))
    (continue-no-filter () (warn "Error setting packet filter."))))



;; Signals packet-filter-error
(defmethod set-filter ((cap pcap-reader) (filter string))
  (restart-case
      (with-slots (pcap_t) cap
        (with-foreign-object (fp 'bpf_program)
          (when (= -1
                   #+sb-thread
                   (sb-thread:with-mutex (*compile-mutex*)
                     (%pcap-compile pcap_t fp filter 1 0))
                   #+openmcl-native-threads
                   (ccl:with-lock-grabbed (*compile-mutex*)
                     (%pcap-compile pcap_t fp filter 1 0))
                   #-(or :sb-thread :openmcl-native-threads)
                   (%pcap-compile pcap_t fp filter 1 0)
                   )
            (error 'packet-filter-error :text (%pcap-geterr pcap_t)))
          (when (= -1 (%pcap-setfilter pcap_t fp))
            (%pcap-freecode fp)
            (error 'packet-filter-error :text (%pcap-geterr pcap_t)))))
    (continue-no-filter () (warn "Error setting packet filter."))))


;; Signals capture-file-error
(defmethod dump ((writer pcap-writer) (buffer vector)
                 &key length origlength sec usec)
  (with-slots (dumper live) writer
    (when live
      (when (null length)
        (setf length (length buffer)))
      (when (null origlength)
        (setf origlength length))
      (when (or (null sec)
                (null usec))
        (multiple-value-bind (s u) (get-time-of-day)
          (cond ((null s) (error 'capture-file-error :text
                                 "Error returned from gettimeofday."))
                (t (setf sec s
                         usec u)))))
      (with-foreign-object (header 'pcap_pkthdr)
        (with-foreign-slots ((ts caplen len) header pcap_pkthdr)
          (with-foreign-slots ((tv_sec tv_usec) ts timeval)
            (setf caplen length
                  len origlength
                  tv_sec sec
                  tv_usec usec)))
        #+:sbcl
        (sb-sys:with-pinned-objects (buffer)
          (%pcap-dump dumper header (sb-sys:vector-sap buffer)))
        #-:sbcl
        (loop
           :with foreign-buffer = (foreign-alloc :uint8 :count length)
           :for i :from 0 :to (- length 1) :do
           (setf (mem-aref foreign-buffer :uint8 i)
                 (aref buffer i))
           :finally (%pcap-dump dumper header foreign-buffer)
           (foreign-free foreign-buffer))))))



;;; ------------------------------
;;; Exported functions


;; Signals network-interface-error
;; Definately not proud of this one, tested on darwin/intel only
;; Should not blow up if something bad happens...
(defun find-all-devs ()
  "Return a list of all network devices that can be opened for capture. Result
list mirrors layout explained in pcap_findalldevs(3)."
  (with-error-buffer (eb)
    (with-foreign-pointer (devp 4)
      (when (= -1 (%pcap-findalldevs devp eb))
        (error 'network-interface-error :text (error-buffer-to-lisp eb)))
      (labels ((ipv4-extract (data)     ; Extract ipv4 address
                 (let ((ptr (inc-pointer (foreign-slot-pointer data
                                                               'sockaddr
                                                               'sa_data)
                                         2)))
                   (with-foreign-object (str :char 16)
                     (let ((res (%inet-ntop 2 ptr str 16)))
                       (cond
                         ((zerop res) nil)
                         (t (foreign-string-to-lisp str)))))))
               (ipv6-extract (data)     ; Extract ipv6 address
                 (let ((ptr (inc-pointer (foreign-slot-pointer data
                                                               'sockaddr
                                                               'sa_data)
                                         6)))
                   (with-foreign-object (str :char 46)
                     (let ((res (%inet-ntop 30 ptr str 46)))
                       (cond
                         ((zerop res) nil)
                         (t (foreign-string-to-lisp str)))))))
               (link-extract (data)     ; Extract link-layer address
                 (%link-ntoa data))
               (process-sockaddr (addr tag) ; Extract address-specific details
                 (when (null-pointer-p addr)
                   (return-from process-sockaddr nil))
                 (with-foreign-slots ((sa_len sa_family) addr sockaddr)
                   (let (output fam)
                     (cond
                       ((= sa_family 0) (setf fam :AF_UNSPEC)
                        (setf output :UNSUPPORTED))
                       ((= sa_family 2) (setf fam :AF_INET)
                        (setf output (ipv4-extract addr)))
                       ((= sa_family 30) (setf fam :AF_INET6)
                        (setf output (ipv6-extract addr)))
                       ((= sa_family 18) (setf fam :AF_LINK)
                        (setf output (link-extract addr)))
                       (t (setf fam :UNSUPPORTED)
                          (setf output :UNSUPPORTED)))
                     (list tag fam output)))))
        (loop :with ifhead = (mem-ref devp :pointer)
           :and lis = ()
           :and addrlist = ()
           :with ifnext = ifhead
           :while (not (null-pointer-p ifnext)) :do
           (with-foreign-slots ((next name description addresses flags) ifnext
                                pcap_if_t)
             (loop :with addrhead = addresses :and newlist = () :with
                addrnext = addrhead :while (not (null-pointer-p addrnext)) :do
                (with-foreign-slots ((next addr netmask broadaddr dstaddr)
                                     addrnext pcap_addr_t)
                  (macrolet ((check-push (list finallist)
                               (let ((g1val (gensym))
                                     (g2tag (gensym))
                                     (g3res (gensym)))
                                 `(loop :for (,g1val ,g2tag) :in ,list :do
                                       (let ((,g3res (process-sockaddr
                                                      ,g1val ,g2tag)))
                                         (when ,g3res
                                           (push ,g3res ,finallist)))))))
                    (check-push `((,dstaddr :dstaddr) (,broadaddr :broadaddr)
                                  (,netmask :netmask) (,addr :addr)) newlist)
                    (push newlist addrlist)
                    (setf newlist nil)
                    (setf addrnext next))))
             (push (list name description flags addrlist) lis)
             (setf addrlist (list))
             (setf ifnext next))
           :finally (%pcap-freealldevs ifhead)
           (return lis))))))


(defmacro with-pcap-interface ((pcaplive iface &rest options) &body body)
  "Call `MAKE-PCAP-LIVE' using `IFACE', `OPTIONS' as arguments and store
the resulting instance in `PCAPLIVE'. Forms in body are wrapped in an
`UNWIND-PROTECT' form that takes care of deallocating resources on
error and also returns packet capture statistics when possible. A restart
is also automatically invoked when `PACKET-FILTER-ERROR' is signalled,
skipping the filter setup."
  `(let ((,pcaplive (make-pcap-live ,iface ,@options)))
     (unwind-protect
          (handler-bind ((packet-filter-error
                          #'(lambda (c)
                              (declare (ignore c))
                              (invoke-restart 'continue-no-filter))))
            (progn ,@body))
       (when (pcap-live-alive ,pcaplive)
         (multiple-value-bind (recv dropped) (stats ,pcaplive)
           (format t "~%~A packets received, ~A dropped~%"
                   recv dropped)))
       (stop ,pcaplive))))


(defmacro with-pcap-reader ((reader file &rest options) &body body)
  "Call `MAKE-PCAP-READER' using `FILE', `OPTIONS' as arguments and store the
resulting instance in `READER'. Forms in body are wrapped in an `UNWIND-PROTECT'
form that takes care of deallocating resources on error. A restart is also
automatically invoked when `PACKET-FILTER-ERROR' is signalled,
skipping the filter setup."
  `(let ((,reader (make-pcap-reader ,file ,@options)))
     (unwind-protect
          (handler-bind ((packet-filter-error
                          #'(lambda (c)
                              (declare (ignore c))
                              (invoke-restart 'continue-no-filter))))
            (progn ,@body))
       (stop ,reader))))


(defmacro with-pcap-writer ((writer file &rest options) &body body)
  "Call `MAKE-PCAP-WRITER' using `FILE', `OPTIONS' as arguments and store
the resulting instance in `WRITER'. Forms in body are wrapped in an
`UNWIND-PROTECT' form that takes care of deallocating resources on error."
  `(let ((,writer (make-pcap-writer ,file ,@options)))
     (unwind-protect
          (progn ,@body)
       (stop ,writer))))



