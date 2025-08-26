#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap
test -e dns.pcap.gz || ln -s "$srcdir/dns.pcap.gz" dns.pcap.gz
test -e dns.pcap.xz || ln -s "$srcdir/dns.pcap.xz" dns.pcap.xz
test -e dns.pcap.lz4 || ln -s "$srcdir/dns.pcap.lz4" dns.pcap.lz4
test -e dns.pcap.zst || ln -s "$srcdir/dns.pcap.zst" dns.pcap.zst
test -e dns.pcap.bz2 || ln -s "$srcdir/dns.pcap.bz2" dns.pcap.bz2
test -e dns_short.pcap || ln -s "$srcdir/dns_short.pcap" dns_short.pcap
test -e dns_short.pcap.gz || ln -s "$srcdir/dns_short.pcap.gz" dns_short.pcap.gz
test -e dns_short.pcap.xz || ln -s "$srcdir/dns_short.pcap.xz" dns_short.pcap.xz
test -e dns_short.pcap.lz4 || ln -s "$srcdir/dns_short.pcap.lz4" dns_short.pcap.lz4
test -e dns_short.pcap.zst || ln -s "$srcdir/dns_short.pcap.zst" dns_short.pcap.zst
test -e dns_short.pcap.bz2 || ln -s "$srcdir/dns_short.pcap.bz2" dns_short.pcap.bz2

../dnscap -g -r dns.pcap 2>dns.out
../dnscap -g -r dns_short.pcap 2>>dns.out
# stdout/stdin test
../dnscap -r dns.pcap -w - | ../dnscap -r - -g 2>>dns.out
# compression tests
../dnscap -g -r dns.pcap.gz 2>>dns.out
../dnscap -g -r dns.pcap.xz 2>>dns.out
../dnscap -g -r dns.pcap.lz4 2>>dns.out
../dnscap -g -r dns.pcap.zst 2>>dns.out
../dnscap -g -r dns.pcap.bz2 2>>dns.out
# compression tests for cut-off'ed PCAP
../dnscap -g -r dns_short.pcap.gz 2>>dns.out
../dnscap -g -r dns_short.pcap.xz 2>>dns.out
../dnscap -g -r dns_short.pcap.lz4 2>>dns.out
../dnscap -g -r dns_short.pcap.zst 2>>dns.out
../dnscap -g -r dns_short.pcap.bz2 2>>dns.out
# compress write test
../dnscap -r dns.pcap -w test -W .pcap.gz
../dnscap -g -r test.20161020.152301.075993.pcap.gz 2>>dns.out

mv dns.out dns.out.old
grep -v "^libgcov profiling error:" dns.out.old > dns.out
rm dns.out.old

diff dns.out "$srcdir/dns.gold2"
