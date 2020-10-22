#!/bin/sh -xe

plugin=`find . -name 'ipcrypt.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the ipcrypt plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -?
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -X
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k tooshort
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -f does_not_exist
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -i 0
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 0
rm -f test4.tmp
touch test4.tmp
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -f test4.tmp

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -p 1 -i 1 -f "$srcdir/test4.sh"
