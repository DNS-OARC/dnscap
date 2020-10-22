#!/bin/sh -xe

plugin=`find . -name 'cryptopan.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the cryptopan plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k tooshort
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -i tooshort
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -a tooshort
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -K "$srcdir/test4.sh" -I "$srcdir/test4.sh" -A "$srcdir/test4.sh"
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -K does_not_exist
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -I does_not_exist
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -A does_not_exist
rm -f test4.tmp
touch test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -K test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -I test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -A test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 0
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 1
