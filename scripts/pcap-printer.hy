(require
  hiolib.rule :readers * *)

(import
  hiolib.rule *
  hiolib.stream *
  hpacket
  hpacket.inet *)

(defmain []
  (let [args (parse-args [["-d" "--debug" :action "store_true" :default False]
                          ["-v" "--verbose" :action "store_true" :default False]
                          ["input"]])]
    (when args.debug
      (setv hpacket.debug True))
    (with [f (open args.input "rb")]
      (let [reader (PcapReader (RawIOStream f))
            printer (#/ hpacket.IndentPrinter :char " " :indent 1 :step 2)]
        (.read-head reader)
        (for [packet (.read-parsed-packets reader)]
          (if args.verbose
              (do
                (print "---")
                (.print packet printer)
                (print "---"))
              (.print printer packet)))))))
