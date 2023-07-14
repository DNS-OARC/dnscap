#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

echo "-- only 1" >test14.out
../dnscap -g -q 1 -r dns.pcap 2>>test14.out
echo "-- not 1" >>test14.out
../dnscap -g -Q 1 -r dns.pcap 2>>test14.out
echo "-- only PTR" >>test14.out
../dnscap -g -q PTR -r dns.pcap 2>>test14.out
echo "-- not PTR" >>test14.out
../dnscap -g -Q PTR -r dns.pcap 2>>test14.out

echo "-- only 1" >>test14.out
../dnscap -g -o use_layers=yes -q 1 -r dns.pcap 2>>test14.out
echo "-- not 1" >>test14.out
../dnscap -g -o use_layers=yes -Q 1 -r dns.pcap 2>>test14.out
echo "-- only PTR" >>test14.out
../dnscap -g -o use_layers=yes -q PTR -r dns.pcap 2>>test14.out
echo "-- not PTR" >>test14.out
../dnscap -g -o use_layers=yes -Q PTR -r dns.pcap 2>>test14.out

mv test14.out test14.out.old
grep -v "^libgcov profiling error:" test14.out.old > test14.out
rm test14.out.old

diff test14.out "$srcdir/test14.gold"
