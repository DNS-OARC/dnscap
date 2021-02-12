#!/bin/sh -xe

plugin=`find . -name 'cryptopant.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the cryptopant plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns.pcap" dns.pcap-dist
ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -r dns.pcap-dist -g -P "$plugin" 2>test3.out || true
if grep -q "no cryptopANT support built in" test3.out 2>/dev/null; then
    echo "No cryptopANT support, skipping tests"
    exit 0
fi

../../src/dnscap -w test3.pcap -r dns.pcap-dist -P "$plugin" -k "$srcdir/keyfile" 2>test3.out
../../src/dnscap -w test3.pcap -r dns6.pcap-dist -P "$plugin" -k "$srcdir/keyfile" 2>>test3.out
../../src/dnscap -r test3.pcap.20161020.152301.075993 -g -P "$plugin" -k "$srcdir/keyfile" -D 2>>test3.out
../../src/dnscap -r test3.pcap.20181127.155200.414188 -g -P "$plugin" -k "$srcdir/keyfile" -D 2>>test3.out

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
