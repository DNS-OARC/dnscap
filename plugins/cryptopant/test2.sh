#!/bin/sh -xe

plugin=`find . -name 'cryptopant.so' | head -n 1`
if [ -z "$plugin" ]; then
    echo "Unable to find the cryptopant plugin"
    exit 1
fi

ln -fs "$srcdir/../../src/test/dns6.pcap" dns6.pcap-dist

../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" 2>test2.out || true
if grep -q "no cryptopANT support built in" test2.out 2>/dev/null; then
    echo "No cryptopANT support, skipping tests"
    exit 0
fi

../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" 2>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -6 24 2>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -c 2>>test2.out
../../src/dnscap -r dns6.pcap-dist -g -P "$plugin" -k "$srcdir/keyfile" -s 2>>test2.out

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test2.out test2.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test2.out.old > test2.out
    rm test2.out.old
fi

# TODO: Remove when #133 is fixed
cat test2.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test2.new
mv test2.new test2.out

diff test2.out "$srcdir/test2.gold"
