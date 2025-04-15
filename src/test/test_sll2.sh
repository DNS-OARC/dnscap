#!/bin/sh -xe

test -e sll2.pcap || ln -s "$srcdir/sll2.pcap" sll2.pcap

../dnscap -g -r sll2.pcap 2>sll2.out

mv sll2.out sll2.out.old
grep -v "^libgcov profiling error:" sll2.out.old > sll2.out
rm sll2.out.old

diff sll2.out "$srcdir/sll2.gold"

../dnscap -o use_layers=yes -g -r sll2.pcap 2>sll2.out

mv sll2.out sll2.out.old
grep -v "^libgcov profiling error:" sll2.out.old > sll2.out
rm sll2.out.old

diff sll2.out "$srcdir/sll2.gold"