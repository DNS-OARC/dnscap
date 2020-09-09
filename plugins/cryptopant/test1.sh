#!/bin/sh -xe

plugin=`find . -name 'cryptopant.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the cryptopant plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" 2>test1.out || true
if grep -q "no cryptopANT support built in" test1.out 2>/dev/null; then
    echo "No cryptopANT support, skipping tests"
    exit 0
fi

! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" 2>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" 2>>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -4 8 2>>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -c 2>>test1.out
../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -s 2>>test1.out
! ../../src/dnscap -r dns.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -c -s 2>>test1.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test1.out test1.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test1.out.old > test1.out
    rm test1.out.old
fi

diff test1.out "$srcdir/test1.gold"
