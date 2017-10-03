#!/bin/sh -xe

../dnscap -g -r dns.pcap-dist 2>dns.out

diff dns.out "$srcdir/dns.gold"
