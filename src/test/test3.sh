#!/bin/sh -xe

../dnscap -g -f -r frags.pcap-dist -o use_layers=yes -o defrag_ipv4=yes -o max_ipv4_fragments_per_packet=64 2>frags.out

# remove timestamp
sed -i -e 's%^\(\[[0-9]*\]\)[^\[]*\[%\1 [%g' frags.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv frags.out frags.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" frags.out.old > frags.out
    rm frags.out.old
fi

# create gold file
cp "$srcdir/dns.gold" frags.gold
sed -i -e 's%^\(\[[0-9]*\]\)[^\[]*\[%\1 [%g' frags.gold
sed -i -e 's%dns.pcap-dist%frags.pcap-dist%g' frags.gold

diff frags.out frags.gold
