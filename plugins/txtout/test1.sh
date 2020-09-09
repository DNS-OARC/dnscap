#!/bin/sh -xe

plugin=`find . -name 'txtout.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the txtout plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
../../src/dnscap -r dns.pcap-dist -g -P "$plugin"
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -s
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -o test1.out
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
