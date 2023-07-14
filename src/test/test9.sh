#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

../dnscap -r dns.pcap -g -B '2016-10-20 15:23:30' -E '2016-10-20 15:24:00' 2>test9.out
../dnscap -r dns.pcap -o use_layers=yes -g -B '2016-10-20 15:23:30' -E '2016-10-20 15:24:00' 2>>test9.out

diff test9.out "$srcdir/test9.gold"
