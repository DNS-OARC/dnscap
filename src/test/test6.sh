#!/bin/sh -xe

test -e dnspad.pcap || ln -s "$srcdir/dnspad.pcap" dnspad.pcap

../dnscap -g -r dnspad.pcap 2>dnspad.out
../dnscap -o use_layers=yes -g -r dnspad.pcap 2>>dnspad.out

diff dnspad.out "$srcdir/dnspad.gold"
