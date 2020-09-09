#!/bin/sh -xe

plugin=`find . -name 'anonaes128.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the anonaes128 plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k tooshort
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -i tooshort
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -4 -K "$srcdir/test4.sh" -I "$srcdir/test4.sh"
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -K does_not_exist
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -I does_not_exist
rm -f test4.tmp
touch test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -K test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -I test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 0
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 1
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -D -4 -k "some 16-byte key" -i "some 16-byte key"
