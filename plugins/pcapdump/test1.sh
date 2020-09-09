#!/bin/sh -xe

plugin=`find . -name 'pcapdump.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the pcapdump plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -dddd -w test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -dddd -f -w test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -dddd -s r -w test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -dddd -s i -w test1.out
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
