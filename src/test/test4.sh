#!/bin/sh -xe

../dnscap -g -T -r 1qtcppadd.pcap-dist 2>padding-no-layers.out
../dnscap -g -T -r 1qtcppadd.pcap-dist -o use_layers=yes 2>padding-layers.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv padding-no-layers.out padding-no-layers.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" padding-no-layers.out.old > padding-no-layers.out
    rm padding-no-layers.out.old
    mv padding-layers.out padding-layers.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" padding-layers.out.old > padding-layers.out
    rm padding-layers.out.old
fi

diff padding-no-layers.out padding-layers.out
