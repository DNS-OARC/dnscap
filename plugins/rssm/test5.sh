#!/bin/sh -xe

plugin=`find . -name 'rssm.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the RSSM plugin"
    exit 1
fi

../../src/dnscap -N -T -r "$srcdir/../../src/test/dnso1tcp.pcap" -P "$plugin" -w test5 -Y -n test5 -A -S -D

diff test5.20180110.112241.543825 "$srcdir/test5.gold"
