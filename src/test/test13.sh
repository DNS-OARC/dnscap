#!/bin/sh -xe

test -f /etc/resolv.conf || exit 0

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

! ../dnscap -a "fake_host-should+not/work" 2>test13.out
cat test13.out
grep -qF "invalid host address" test13.out

if [ "`uname`" = "OpenBSD" ]; then
    # IPv6 addresses in BPF seems to segfault on OpenBSD and doing host and
    # not host throws generic pcap_compile error
    ../dnscap -a 127.0.0.1 -r dns.pcap -g -dddd
    ../dnscap -z 127.0.0.1 -r dns.pcap -g -dddd
    ../dnscap -A 127.0.0.1 -r dns.pcap -g -dddd
    ../dnscap -Z 127.0.0.1 -r dns.pcap -g -dddd
    ../dnscap -Y 127.0.0.1 -r dns.pcap -g -dddd
else
    ../dnscap -a 127.0.0.1 -a ::1 -r dns.pcap -g -dddd
    ../dnscap -z 127.0.0.1 -z ::1 -r dns.pcap -g -dddd
    ../dnscap -A 127.0.0.1 -A ::1 -r dns.pcap -g -dddd
    ../dnscap -Z 127.0.0.1 -Z ::1 -r dns.pcap -g -dddd
    ../dnscap -Y 127.0.0.1 -Y ::1 -r dns.pcap -g -dddd
fi
if [ "$TEST_DNSCAP_WITH_NETWORK" = "1" ]; then
    ../dnscap -a google.com -r dns.pcap -g -dddd
fi
../dnscap -Y 127.0.0.1 -r dns.pcap -g
../dnscap -Y 8.8.8.8 -r dns.pcap -g
