#!/bin/sh -xe

plugin=`find . -name 'asudp.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the asudp plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
#../../src/dnscap -r dns.pcap-dist -g -P "$plugin"
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X

ln -fs "$srcdir/../../src/test/dnso1tcp.pcap" dnso1tcp.pcap-dist
ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -T -r dnso1tcp.pcap-dist -w - -P "$plugin" | ../../src/dnscap -r - -g 2>test1.out
../../src/dnscap -T -r dns6.pcap-dist -w - -P "$plugin" | ../../src/dnscap -r - -g 2>>test1.out

mv test1.out test1.out.old
grep -v "^libgcov profiling error:" test1.out.old > test1.out
rm test1.out.old

diff test1.out "$srcdir/test1.gold"
