#!/bin/sh -xe

txtout="../../plugins/txtout/.libs/txtout.so"

rm -f test7.out test7.layer.out

for what in dnso1tcp.pcap-dist 1qtcpnosyn.pcap-dist do1t-nosyn-1nolen.pcap-dist dnso1tcp-midmiss.pcap-dist; do
    ../dnscap -r "$what" -g -T 2>>test7.out
    ../dnscap -r "$what" -g -T -o use_layers=yes 2>>test7.layer.out
    if [ -f "$txtout" ]; then
        ../dnscap -r "$what" -T -P "$txtout" >>test7.out
        ../dnscap -r "$what" -T -o use_layers=yes -P "$txtout" >>test7.layer.out
    fi
done

echo "" >>test7.out
echo "Enabling parse_ongoing_tcp and allow_reset_tcpstate" >>test7.out
echo "" >>test7.out
echo "" >>test7.layer.out
echo "Enabling parse_ongoing_tcp and allow_reset_tcpstate" >>test7.layer.out
echo "" >>test7.layer.out

for what in dnso1tcp.pcap-dist 1qtcpnosyn.pcap-dist do1t-nosyn-1nolen.pcap-dist dnso1tcp-midmiss.pcap-dist; do
    ../dnscap -r "$what" -g -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes 2>>test7.out
    ../dnscap -r "$what" -g -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes 2>>test7.layer.out
    if [ -f "$txtout" ]; then
        ../dnscap -r "$what" -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -P "$txtout" >>test7.out
        ../dnscap -r "$what" -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes -P "$txtout" >>test7.layer.out
    fi
done

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test7.out test7.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test7.out.old > test7.out
    rm test7.out.old
    mv test7.layer.out test7.layer.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test7.layer.out.old > test7.layer.out
    rm test7.layer.out.old
fi

# TODO: Remove when #133 is fixed
cat test7.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test7.new
mv test7.new test7.out
cat test7.layer.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test7.layer.new
mv test7.layer.new test7.layer.out

diff test7.out "$srcdir/test7.gold"
diff test7.layer.out "$srcdir/test7.gold"
