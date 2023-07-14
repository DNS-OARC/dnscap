#!/bin/sh -xe

test -e 1qtcppadd.pcap || ln -s "$srcdir/1qtcppadd.pcap" 1qtcppadd.pcap

../dnscap -g -T -r 1qtcppadd.pcap 2>padding-no-layers.out
../dnscap -g -T -r 1qtcppadd.pcap -o use_layers=yes 2>padding-layers.out

diff padding-no-layers.out padding-layers.out
