#!/bin/sh -xe

../dnscap -g -r dns.pcap-dist 2>no-layers.out
../dnscap -g -r dns.pcap-dist -o use_layers=yes 2>layers.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv no-layers.out no-layers.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" no-layers.out.old > no-layers.out
    rm no-layers.out.old
    mv layers.out layers.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" layers.out.old > layers.out
    rm layers.out.old
fi

diff no-layers.out layers.out
