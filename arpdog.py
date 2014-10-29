from scapy.all import *


eth_=Ether()
ip_=IP()
ip_.dst="10.0.0.202"
udp_ = UDP()
udp_.dport=10000
udp_.payload="ALERT:: Gateway mac changed from ABC to DEF"
eth_.dst="00:0c:29:c3:e9:5e"
pkt=eth_/ip_/udp_
sendp(str(pkt))

