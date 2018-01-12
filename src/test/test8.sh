#!/bin/sh -xe

rm -f test8.out test8.layer.out

for what in dnsotcp-many1pkt.pcap-dist dnsotcp-manyopkts.pcap-dist; do
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes 2>>test8.out
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o use_layers=yes 2>>test8.layer.out
done

for what in dnso1tcp-bighole.pcap-dist; do
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o allow_reset_tcpstate=yes 2>>test8.out
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes 2>>test8.layer.out
done

osrel=`uname -s`
if [ "$osrel" = "OpenBSD" ]; then
    mv test8.out test8.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test8.out.old > test8.out
    rm test8.out.old
    mv test8.layer.out test8.layer.out.old
    grep -v "^dnscap.*WARNING.*symbol.*relink" test8.layer.out.old > test8.layer.out
    rm test8.layer.out.old
fi

# TODO: Remove when #133 is fixed
cat test8.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test8.new
mv test8.new test8.out
cat test8.layer.out | \
  sed 's%,CLASS4096,OPT,%,4096,4096,%' | \
  sed 's%,CLASS512,OPT,%,512,512,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=4096,%,4096,4096,0,edns0[len=0,UDP=4096,%' | \
  sed 's%,41,41,0,edns0\[len=0,UDP=512,%,512,512,0,edns0[len=0,UDP=512,%' >test8.layer.new
mv test8.layer.new test8.layer.out

diff test8.out "$srcdir/test8.gold"
diff test8.layer.out "$srcdir/test8.gold"
