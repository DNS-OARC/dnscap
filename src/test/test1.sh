#!/bin/sh -xe

../dnscap -g -r dns.pcap-dist 2>dns.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv dns.out dns.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" dns.out.old > dns.out
    rm dns.out.old
fi

diff dns.out "$srcdir/dns.gold"
