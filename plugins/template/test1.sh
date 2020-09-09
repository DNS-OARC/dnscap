#!/bin/sh -xe

plugin=`find . -name 'template.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the template plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
../../src/dnscap -r dns.pcap-dist -g -P "$plugin"
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
