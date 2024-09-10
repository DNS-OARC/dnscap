#!/bin/sh -xe

test -e icmp.pcap || ln -s "$srcdir/icmp.pcap" icmp.pcap

../dnscap -g -I -r icmp.pcap 2>test_icmp.out

mv test_icmp.out test_icmp.out.old
grep -v "^libgcov profiling error:" test_icmp.out.old > test_icmp.out
rm test_icmp.out.old

diff test_icmp.out "$srcdir/icmp.gold"
