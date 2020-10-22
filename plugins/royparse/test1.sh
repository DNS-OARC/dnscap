#!/bin/sh -xe

plugin=`find . -name 'royparse.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the royparse plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
../../src/dnscap -r dns.pcap-dist -g -P "$plugin"
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -q test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -r test1.out
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
