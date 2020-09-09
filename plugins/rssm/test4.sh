#!/bin/sh -xe

plugin=`find . -name 'rssm.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the RSSM plugin"
    exit 1
fi

../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -?
! ../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -X
! ../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -s s -s s -S
! ../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -a a -a a -A
! ../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -Y
../../src/dnscap -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -D -w test4 -w test4 -n n -n n -s test4.src -a test4.agg
