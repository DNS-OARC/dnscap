#!/bin/sh -xe

../dnscap -r dns6.pcap-dist -6 -g 2>test10.out
../dnscap -r dns6.pcap-dist -6 -o use_layers=yes -g 2>>test10.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test10.out test10.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test10.out.old > test10.out
    rm test10.out.old
fi

# TODO: Remove when #133 is fixed
cat test10.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test10.new
mv test10.new test10.out

diff test10.out "$srcdir/test10.gold"
