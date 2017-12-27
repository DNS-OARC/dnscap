#!/bin/sh -xe

osrel=`uname -s`

clean_out() {
    if [ "$osrel" = "OpenBSD" ]; then
        mv vlan11.out vlan11.out.old
        grep -v "^dnscap.*WARNING.*symbol.*relink" vlan11.out.old > vlan11.out
        rm vlan11.out.old
    fi
}

../dnscap -g -r vlan11.pcap-dist 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -L 4095 2>vlan11.out
clean_out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -L 11 2>vlan11.out
clean_out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 10 2>vlan11.out
test -f vlan11.out && ! test -s vlan11.out
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 4095 2>vlan11.out
clean_out
diff vlan11.out "$srcdir/vlan11.gold"
../dnscap -g -r vlan11.pcap-dist -o use_layers=yes -L 11 2>vlan11.out
clean_out
diff vlan11.out "$srcdir/vlan11.gold"
