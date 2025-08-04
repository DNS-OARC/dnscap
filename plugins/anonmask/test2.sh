#!/bin/sh -xe

plugin=`find . -name 'anonmask.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the anonmask plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" 2>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 24 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 32 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 64 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -6 96 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -c 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -s 2>>test2.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test2.out test2.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test2.out.old > test2.out
    rm test2.out.old
fi

diff test2.out "$srcdir/test2.gold"
