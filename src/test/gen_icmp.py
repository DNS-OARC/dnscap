import sys
from scapy.all import *

pcap = sys.argv[1]

pkts = []
pkts.append(Ether()/IPv6(dst="2001:db8:dead::1")/ICMPv6DestUnreach())
pkts.append(Ether()/IP(dst="0.0.0.0")/ICMP(type=3))

wrpcap(pcap, pkts)