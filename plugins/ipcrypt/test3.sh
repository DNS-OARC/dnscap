#!/bin/sh -xe

plugin=`find . -name 'ipcrypt.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the ipcrypt plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist
ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -w test3.pcap -r dns.pcap-dist -P "$plugin" -k "some 16-byte key" 2>test3.out
../../src/dnscap -w test3.pcap -r dns6.pcap-dist -6 -P "$plugin" -k "some 16-byte key" -6 2>>test3.out
../../src/dnscap -r test3.pcap.20161020.152301.075993 -g -P "$plugin" -k "some 16-byte key" -D 2>>test3.out
../../src/dnscap -r test3.pcap.20181127.155200.414188 -6 -g -P "$plugin" -k "some 16-byte key" -6 -D 2>>test3.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test3.out test3.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test3.out.old > test3.out
    rm test3.out.old
fi

# TODO: Remove when #133 is fixed
cat test3.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test3.new
mv test3.new test3.out

diff test3.out "$srcdir/test3.gold"
