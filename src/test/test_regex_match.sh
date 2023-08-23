#!/bin/sh -xe

../dnscap -g -r dns.pcap -x 'ns1' 2>test_regex_match.out
../dnscap -g -r dns.pcap -X 'ns1' 2>>test_regex_match.out
../dnscap -g -r dns.pcap -x 'ns1' -X 'ns1' 2>>test_regex_match.out

mv test_regex_match.out test_regex_match.out.old
grep -v "^libgcov profiling error:" test_regex_match.out.old > test_regex_match.out
rm test_regex_match.out.old

diff test_regex_match.out "$srcdir/test_regex_match.gold"
