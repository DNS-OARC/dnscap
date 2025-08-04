#!/bin/sh -xe

test -e vlan11.pcap || ln -s "$srcdir/vlan11.pcap" vlan11.pcap

osrel=`uname -s`

../dnscap -g -r vlan11.pcap 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap -L 4095 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap -L 11 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap -o use_layers=yes 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap -o use_layers=yes -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap -o use_layers=yes -L 4095 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap -o use_layers=yes -L 11 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
