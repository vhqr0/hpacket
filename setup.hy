(setv
  version "0.1.0"
  requires ["hy~=0.27.0" "hyrule~=0.4.0" "hiolib~=0.1.0"])

(require
  hyrule :readers * *)

(#/ setuptools.setup
  :name "hpacket"
  :version version
  :install-requires requires
  :author "vhqr"
  :description "A concise replacement for Scapy in building and parsing network packets"
  :packages (#/ setuptools.find-packages))
