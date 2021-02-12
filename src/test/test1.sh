#!/bin/sh -xe

../dnscap -g -r dns.pcap-dist 2>dns.out

mv dns.out dns.out.old
grep -v "^libgcov profiling error:" dns.out.old > dns.out
rm dns.out.old

diff dns.out "$srcdir/dns.gold"
