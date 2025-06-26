#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap
test -e dns.pcap.gz || ln -s "$srcdir/dns.pcap.gz" dns.pcap.gz
test -e dns.pcap.xz || ln -s "$srcdir/dns.pcap.xz" dns.pcap.xz
test -e dns.pcap.lz4 || ln -s "$srcdir/dns.pcap.lz4" dns.pcap.lz4
test -e dns.pcap.zst || ln -s "$srcdir/dns.pcap.zst" dns.pcap.zst

../dnscap -g -r dns.pcap 2>dns.out
# stdout/stdin test
../dnscap -r dns.pcap -w - | ../dnscap -r - -g 2>>dns.out
# compression tests
../dnscap -g -r dns.pcap.gz 2>>dns.out
../dnscap -g -r dns.pcap.xz 2>>dns.out
../dnscap -g -r dns.pcap.lz4 2>>dns.out
../dnscap -g -r dns.pcap.zst 2>>dns.out
# compress write test
../dnscap -r dns.pcap -w test -W .pcap.gz
../dnscap -g -r test.20161020.152301.075993.pcap.gz 2>>dns.out

mv dns.out dns.out.old
grep -v "^libgcov profiling error:" dns.out.old > dns.out
rm dns.out.old

diff dns.out "$srcdir/dns.gold2"
