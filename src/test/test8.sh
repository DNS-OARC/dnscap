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

diff test8.out "$srcdir/test8.gold"
diff test8.layer.out "$srcdir/test8.gold"
