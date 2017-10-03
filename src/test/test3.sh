#!/bin/sh -xe

../dnscap -g -f -r frags.pcap-dist -o use_layers=yes -o defrag_ipv4=yes -o max_ipv4_fragments_per_packet=64 2>frags.out

# remove timestamp
sed -i -e 's%^\(\[[0-9]*\]\)[^\[]*\[%\1 [%g' frags.out

diff frags.out "$srcdir/frags.gold"
