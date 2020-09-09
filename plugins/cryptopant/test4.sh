#!/bin/sh -xe

plugin=`find . -name 'cryptopant.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the cryptopant plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

# ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" 2>test1.out || true
# if grep -q "no cryptopANT support built in" test1.out 2>/dev/null; then
#     echo "No cryptopANT support, skipping tests"
#     exit 0
# fi

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 0
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 1
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -4 99
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -6 999
