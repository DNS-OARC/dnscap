#!/bin/sh -xe

test -e dns6.pcap || ln -s "$srcdir/dns6.pcap" dns6.pcap

../dnscap -r dns6.pcap -g 2>test10.out
../dnscap -r dns6.pcap -o use_layers=yes -g 2>>test10.out

diff test10.out "$srcdir/test10.gold"
