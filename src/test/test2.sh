#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

../dnscap -g -r dns.pcap 2>no-layers.out
../dnscap -g -r dns.pcap -o use_layers=yes 2>layers.out

diff no-layers.out layers.out
