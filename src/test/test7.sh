#!/bin/sh -xe

txtout="../../plugins/txtout/.libs/txtout.so"

rm -f test7.out test7.layer.out

for what in dnso1tcp.pcap 1qtcpnosyn.pcap do1t-nosyn-1nolen.pcap dnso1tcp-midmiss.pcap; do
    test -e "$what" || ln -s "$srcdir/$what" "$what"

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

for what in dnso1tcp.pcap 1qtcpnosyn.pcap do1t-nosyn-1nolen.pcap dnso1tcp-midmiss.pcap; do
    test -e "$what" || ln -s "$srcdir/$what" "$what"

    ../dnscap -r "$what" -g -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes 2>>test7.out
    ../dnscap -r "$what" -g -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes 2>>test7.layer.out
    if [ -f "$txtout" ]; then
        ../dnscap -r "$what" -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -P "$txtout" >>test7.out
        ../dnscap -r "$what" -T -o parse_ongoing_tcp=yes -o allow_reset_tcpstate=yes -o use_layers=yes -P "$txtout" >>test7.layer.out
    fi
done

mv test7.out test7.out.old
grep -v "^libgcov profiling error:" test7.out.old > test7.out
rm test7.out.old
diff test7.out "$srcdir/test7.gold"
mv test7.layer.out test7.layer.out.old
grep -v "^libgcov profiling error:" test7.layer.out.old > test7.layer.out
rm test7.layer.out.old
diff test7.layer.out "$srcdir/test7.gold"
