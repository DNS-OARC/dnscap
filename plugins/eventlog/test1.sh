#!/bin/sh -xe

plugin=`find . -name 'eventlog.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the eventlog plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist
ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist
ln -fs "$srcdir/../../src/test/dnso1tcp.pcap" dnso1tcp.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
../../src/dnscap -r dns.pcap-dist -g -P "$plugin"
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -o test1.out -o test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -s
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -t
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -n test
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X

../../src/dnscap -r dns6.pcap-dist -g -P "$plugin"
../../src/dnscap -T -r dnso1tcp.pcap-dist -g -P "$plugin"
