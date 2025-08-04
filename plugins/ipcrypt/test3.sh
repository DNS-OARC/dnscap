#!/bin/sh -xe

plugin=`find . -name 'ipcrypt.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the ipcrypt plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist
ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -w test3.pcap -r dns.pcap-dist -P "$plugin" -k "some 16-byte key" 2>test3.out
../../src/dnscap -w test3.pcap -r dns6.pcap-dist -P "$plugin" -k "some 16-byte key" -6 2>>test3.out
../../src/dnscap -r test3.pcap.20161020.152301.075993 -g -P "$plugin" -k "some 16-byte key" -D 2>>test3.out
../../src/dnscap -r test3.pcap.20181127.155200.414188 -g -P "$plugin" -k "some 16-byte key" -6 -D 2>>test3.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test3.out test3.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test3.out.old > test3.out
    rm test3.out.old
fi

diff test3.out "$srcdir/test3.gold"
