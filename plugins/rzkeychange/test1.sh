#!/bin/sh -xe

plugin=`find . -name 'rzkeychange.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the rzkeychange plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -n text -n text
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -s text -s text
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -z text -z text
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k text -k text
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -a 1 -a 2 -a 3 -a 4 -a 5 -a 6 -a 7 -a 8 -a 9 -a 10 -a 11

# LDNS resolver needs /etc/resolv.conf
test -f /etc/resolv.conf || exit 0
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -D -t -p 5353 -a 127.0.0.1 -n n -s s -z example.com -k k
