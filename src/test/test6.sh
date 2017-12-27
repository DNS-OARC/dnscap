#!/bin/sh -xe

../dnscap -g -r dnspad.pcap-dist 2>dnspad.out
../dnscap -o use_layers=yes -g -r dnspad.pcap-dist 2>>dnspad.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv dnspad.out dnspad.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" dnspad.out.old > dnspad.out
    rm dnspad.out.old
fi

diff dnspad.out "$srcdir/dnspad.gold"
