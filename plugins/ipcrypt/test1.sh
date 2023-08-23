#!/bin/sh -xe

plugin=`find . -name 'ipcrypt.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the ipcrypt plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" 2>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "some 16-byte key" 2>>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "some 16-byte key" -c 2>>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "some 16-byte key" -s 2>>test1.out
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "some 16-byte key" -c -s 2>>test1.out

ln -fs "$srcdir/../../src/test/edns.pcap" edns.pcap-dist

../../src/dnscap -r edns.pcap-dist -g -P "$plugin" -k "some 16-byte key" -e 2>>test1.out
../../src/dnscap -r edns.pcap-dist -g -P "$plugin" -k "some 16-byte key" -E 2>>test1.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test1.out test1.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test1.out.old > test1.out
    rm test1.out.old
fi

diff test1.out "$srcdir/test1.gold"
