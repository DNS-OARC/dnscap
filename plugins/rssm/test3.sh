#!/bin/sh -xe

plugin=`find . -name 'rssm.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the RSSM plugin"
    exit 1
fi

../../src/dnscap -N -T -6 -r "$srcdir/../../src/test/dns6.pcap" -P "$plugin" -w test3 -Y -n test3 -A -S -D

diff test3.20181127.155200.414188 "$srcdir/test3.gold"
