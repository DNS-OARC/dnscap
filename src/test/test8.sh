#!/bin/sh -xe

rm -f test8.out test8.layer.out

for what in dnsotcp-many1pkt.pcap dnsotcp-manyopkts.pcap; do
    test -e "$what" || ln -s "$srcdir/$what" "$what"

    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes 2>>test8.out
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o use_layers=yes 2>>test8.layer.out
done

for what in dnso1tcp-bighole.pcap; do
    test -e "$what" || ln -s "$srcdir/$what" "$what"

    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o allow_reset_tcpstate=yes 2>>test8.out
    ../dnscap -r "$what" -g -T -o reassemble_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes 2>>test8.layer.out
done

diff test8.out "$srcdir/test8.gold"
diff test8.layer.out "$srcdir/test8.gold"
