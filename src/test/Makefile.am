MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = test*.log test*.trs \
  dns.out \
  no-layers.out layers.out \
  frags.out frags.gold \
  padding-no-layers.out padding-layers.out \
  vlan11.out \
  dnspad.out \
  test7.out test7.layer.out \
  test8.out \
  test9.out \
  test10.out \
  test11.out \
  test12.out test12.20161020.152301.075993.gz \
  test13.out \
  test14.out \
  test_regex_match.out \
  edns.out \
  test_icmp.out

TESTS = test1.sh test2.sh test3.sh test4.sh test5.sh test6.sh test7.sh \
  test8.sh test9.sh test10.sh test11.sh test12.sh test13.sh test14.sh \
  test_regex_match.sh test_edns.sh test_icmp.sh

EXTRA_DIST = $(TESTS) \
  dns.gold dns.pcap \
  frags.pcap \
  1qtcppadd.pcap \
  vlan11.gold vlan11.pcap \
  dnspad.gold dnspad.pcap \
  test7.gold 1qtcpnosyn.pcap dnso1tcp.pcap do1t-nosyn-1nolen.pcap \
  dnso1tcp-midmiss.pcap \
  test8.gold dnsotcp-many1pkt.pcap dnsotcp-manyopkts.pcap \
  dnso1tcp-bighole.pcap \
  test9.gold \
  dns6.pcap test10.gold \
  test14.gold \
  test_regex_match.gold \
  edns.pcap edns.gold \
  gen_icmp.py icmp.pcap icmp.gold
