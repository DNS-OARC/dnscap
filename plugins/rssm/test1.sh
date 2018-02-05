#!/bin/sh -xe

plugin=`find . -name 'rssm.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the RSSM plugin"
    exit 1
fi

../../src/dnscap -N -T -r "$srcdir/../../src/test/dns.pcap" -P "$plugin" -w test1 -Y -n test1 -A -S -D

diff test1.20161020.152301.075993 "$srcdir/test1.gold"
