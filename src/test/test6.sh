#!/bin/sh -xe

../dnscap -g -r dnspad.pcap-dist 2>dnspad.out
../dnscap -o use_layers=yes -g -r dnspad.pcap-dist 2>>dnspad.out

diff dnspad.out "$srcdir/dnspad.gold"
