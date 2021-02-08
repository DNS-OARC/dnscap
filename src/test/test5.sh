#!/bin/sh -xe

osrel=`uname -s`

../dnscap -g -r vlan11.pcap-dist 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -L 4095 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -L 11 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 4095 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 11 2>vlan11.out
diff vlan11.out "$srcdir/vlan11.gold"
