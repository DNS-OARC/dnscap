#!/bin/sh -xe

plugin=`find . -name 'anonaes128.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the anonaes128 plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -r dns6.pcap-dist -w test3.pcap -P "$plugin" -k "some 16-byte key" -i "some 16-byte key" 2>test3.out
../../src/dnscap -r test3.pcap.20181127.155200.414188 -g -P "$plugin" -D -k "some 16-byte key" -i "some 16-byte key" 2>>test3.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test3.out test3.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test3.out.old > test3.out
    rm test3.out.old
fi

diff test3.out "$srcdir/test3.gold"
