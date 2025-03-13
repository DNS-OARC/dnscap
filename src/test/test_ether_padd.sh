#!/bin/sh -xe

test -e ether_padd.pcap || ln -s "$srcdir/ether_padd.pcap" ether_padd.pcap
test -e ipv6-with-ethernet-padding.pcap || ln -s "$srcdir/ipv6-with-ethernet-padding.pcap" ipv6-with-ethernet-padding.pcap

../dnscap -T -u 443 -g -r ether_padd.pcap 2>ether_padd.out
../dnscap -T -g -r ipv6-with-ethernet-padding.pcap 2>>ether_padd.out

mv ether_padd.out ether_padd.out.old
grep -v "^libgcov profiling error:" ether_padd.out.old > ether_padd.out
rm ether_padd.out.old

diff ether_padd.out "$srcdir/ether_padd.gold"

../dnscap -o use_layers=yes -T -u 443 -g -r ether_padd.pcap 2>ether_padd.out
../dnscap -o use_layers=yes -T -g -r ipv6-with-ethernet-padding.pcap 2>>ether_padd.out

mv ether_padd.out ether_padd.out.old
grep -v "^libgcov profiling error:" ether_padd.out.old > ether_padd.out
rm ether_padd.out.old

diff ether_padd.out "$srcdir/ether_padd.gold"
