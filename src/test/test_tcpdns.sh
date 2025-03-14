#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

../dnscap -g -r dns.pcap -w tcpdns.out -o dump_format=tcpdns

( sha256sum tcpdns.out.20161020.152301.075993 || sha256 tcpdns.out.20161020.152301.075993 ) | grep 13e878e91ded44997a82324f28c06f23cf639954cc33eeeff8f3c5068c5ed964