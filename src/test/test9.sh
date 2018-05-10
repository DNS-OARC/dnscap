#!/bin/sh -xe

../dnscap -r dns.pcap-dist -g -B '2016-10-20 15:23:30' -E '2016-10-20 15:24:00' 2>test9.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test9.out test9.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test9.out.old > test9.out
    rm test9.out.old
fi

# TODO: Remove when #133 is fixed
cat test9.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test9.new
mv test9.new test9.out

diff test9.out "$srcdir/test9.gold"
