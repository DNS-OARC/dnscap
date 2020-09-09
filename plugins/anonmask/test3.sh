#!/bin/sh -xe

plugin=`find . -name 'anonmask.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the anonmask plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -4 99
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -6 999
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 0
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 1
