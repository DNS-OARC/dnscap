#!/bin/sh -xe

plugin=`find . -name 'ipcrypt.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the ipcrypt plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 -k "some 16-byte key" 2>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 -k "some 16-byte key" -c 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 -k "some 16-byte key" -s 2>>test2.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test2.out test2.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test2.out.old > test2.out
    rm test2.out.old
fi

diff test2.out "$srcdir/test2.gold"
