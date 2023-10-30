(require
  hiolib.rule :readers * *
  hiolib.struct *
  hpacket *
  hpacket.inet.inet *)

(import
  enum [IntEnum]
  hiolib.struct *
  hpacket *
  hpacket.inet.inet *
  hpacket.inet.dns *)


;;; dhcpv4

(setv DHCPv4-MAGIC b"\x63\x82\x53\x63")

(defclass DHCPv4Op [IntEnum]
  (setv Req 1 Rep 2))

(defclass DHCPv4MsgType [IntEnum]
  (setv Discover 1
        Offer    2
        Request  3
        Decline  4
        ACK      5
        NAK      6
        Release  7
        Inform   8))

(define-opt-dict DHCPv4Opt
  [Pad           0
   End         255
   MsgType      53
   ServerID     54
   ClientID     61
   HostName     12
   VendorClass  60
   VendorSpec   43
   ReqAddr      50
   ReqParam     55
   LeaseTime    51
   RenewalTime  58
   RebindTime   59
   SubnetMask    1
   Router        3
   DNSServer     6]
  [[int type :len 1 :to (normalize it DHCPv4Opt)]
   [varlen data
    :len (if (in type #(0 255)) 0 1)
    :from (DHCPv4Opt.pack type it)
    :to (DHCPv4Opt.unpack type it)]])

(defpacket [(UDPService.register UDPService.DHCPv4Cli UDPService.DHCPv4Srv)] DHCPv4 [PrintOptsMixin]
  [[int op :len 1 :to (normalize it DHCPv4Op)]
   [int htype :len 1]
   [int hlen :len 1]
   [int hops :len 1]
   [int xid :len 4]
   [int secs :len 2]
   [int flags :len 2]
   [struct [[ciaddr] [yiaddr] [siaddr] [giaddr]] :struct (async-name IPv4Addr) :repeat 4]
   [struct [chaddr] :struct (async-name MACAddr)]
   [bytes pad :len 10]
   [bytes sname :len 64]
   [bytes file :len 128]
   [bytes magic :len 4]
   [struct [opts] :struct (async-name DHCPv4OptListStruct)]]
  [[op DHCPv4Op.Req] [htype 1] [hlen 6] [hops 0] [xid 0] [secs 0] [flags 0]
   [ciaddr IPv4-ZERO] [yiaddr IPv4-ZERO] [siaddr IPv4-ZERO] [giaddr IPv4-ZERO]
   [chaddr MAC-ZERO] [pad (bytes 10)] [sname (bytes 64)] [file (bytes 128)]
   [magic DHCPv4-MAGIC] [opts #()]]

  (setv disp-whitelist #("op" #("hops") "xid" "ciaddr" "yiaddr" "siaddr" "giaddr" "chaddr")))

(define-int-opt DHCPv4Opt MsgType 1 DHCPv4MsgType)

(define-atom-struct-opt DHCPv4Opt ReqAddr IPv4Addr)

(define-atom-struct-opt DHCPv4Opt ReqParam
  [int params
   :len 1
   :repeat-while (async-wait (.peek reader))
   :to-each (normalize it DHCPv4Opt)])

(define-int-opt DHCPv4Opt LeaseTime   4)
(define-int-opt DHCPv4Opt RenewalTime 4)
(define-int-opt DHCPv4Opt RebindTime  4)

(define-atom-struct-opt DHCPv4Opt SubnetMask IPv4Addr)
(define-atom-struct-opt DHCPv4Opt Router     IPv4AddrList)
(define-atom-struct-opt DHCPv4Opt DNSServer  IPv4AddrList)


;;; dhcpv6

(defclass DHCPv6MsgType [IntEnum]
  (setv Solicit    1
        Advertise  2
        Request    3
        Confirm    4
        Renew      5
        Rebind     6
        Reply      7
        Release    8
        Decline    9
        Reconf    10
        InfoReq   11
        RelayForw 12
        RelayRepl 13))

(define-opt-dict DHCPv6Opt
  [ClientID     1
   ServerID     2
   RelayMsg     9
   Status      13
   Pref         7
   VendorClass 16
   VendorSpec  17
   IANA         3
   IATA         4
   IAPD        25
   IAAddr       5
   IAPrefix    26
   RapidCommit 14
   ReqOpt       6
   ElapsedTime  8
   RefreshTime 32
   DNSServer   23
   DNSSearch   24
   NTPServer   56]
  [[int type :len 2 :to (normalize it DHCPv6Opt)]
   [varlen data
    :len 2
    :from (DHCPv6Opt.pack type it)
    :to (DHCPv6Opt.unpack type it)]])

(defpacket [(UDPService.register UDPService.DHCPv6Cli UDPService.DHCPv6Cli)] DHCPv6 [PrintOptsMixin]
  [[int type :len 1 :to (normalize it DHCPv6MsgType)]
   [int xid :len 3]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[type DHCPv6MsgType.Solicit] [xid 0] [opts #()]]
  (setv disp-whitelist #("type" "xid")))

(define-struct-opt DHCPv6Opt Status
  [[int code :len 2]
   [all msg]])

(define-int-opt DHCPv6Opt Pref 1)

(define-packet-opt DHCPv6Opt IANA [PrintOptsMixin]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]]
  (setv disp-whitelist #("iaid" #("T1") #("T2"))))

(define-packet-opt DHCPv6Opt IATA [PrintOptsMixin]
  [[int iaid :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[iaid 0] [opts #()]]
  (setv disp-whitelist #("iaid")))

(define-packet-opt DHCPv6Opt IAPD [PrintOptsMixin]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name  DHCPv6OptListStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]]
  (setv disp-whitelist #("iaid" #("T1") #("T2"))))

(define-packet-opt DHCPv6Opt IAAddr [PrintOptsMixin]
  [[struct [addr] :struct (async-name IPv6Addr)]
   [int preftime :len 4]
   [int validtime :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[addr IPv6-ZERO] [iaid 0] [preftime 0] [validtime 0] [opts #()]]
  (setv disp-whitelist #("addr" "iaid" #("preftime") #("validtime"))))

(define-packet-opt DHCPv6Opt IAPrefix [PrintOptsMixin]
  [[int preftime :len 4]
   [int validtime :len 4]
   [int plen :len 1]
   [struct [prefix] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[preftime 0] [validtime 0] [plen 64] [prefix IPv6-ZERO] [opts #()]]
  (setv disp-whitelist #(#("preftime") #("validtime") "plen" "prefix")))

(define-atom-struct-opt DHCPv6Opt ReqOpt
  [int opts
   :len 2
   :repeat-while (async-wait (.peek reader))
   :to-each (normalize it DHCPv6Opt)])

(define-int-opt DHCPv6Opt ElapsedTime 2)
(define-int-opt DHCPv6Opt RefreshTime 4)

(define-atom-struct-opt DHCPv6Opt DNSServer IPv6AddrList)
(define-atom-struct-opt DHCPv6Opt DNSSearch DNSNameList)
(define-atom-struct-opt DHCPv6Opt NTPServer IPv6AddrList)
