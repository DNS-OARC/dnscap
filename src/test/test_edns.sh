#!/bin/sh -xe

test -e edns.pcap || ln -s "$srcdir/edns.pcap" edns.pcap

../dnscap -g -r edns.pcap 2>edns.out

mv edns.out edns.out.old
grep -v "^libgcov profiling error:" edns.out.old > edns.out
rm edns.out.old

diff edns.out "$srcdir/edns.gold"
