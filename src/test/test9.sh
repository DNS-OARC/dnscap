#!/bin/sh -xe

../dnscap -r dns.pcap-dist -g -B '2016-10-20 15:23:30' -E '2016-10-20 15:24:00' 2>test9.out
../dnscap -r dns.pcap-dist -o use_layers=yes -g -B '2016-10-20 15:23:30' -E '2016-10-20 15:24:00' 2>>test9.out

diff test9.out "$srcdir/test9.gold"
