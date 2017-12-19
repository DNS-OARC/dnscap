MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = test*.log test*.trs \
    *.pcap-dist \
    dns.out \
    no-layers.out layers.out \
    frags.out \
    padding-no-layers.out padding-layers.out

TESTS = test1.sh test2.sh test3.sh test4.sh

test1.sh: dns.pcap-dist

test2.sh: dns.pcap-dist

test3.sh: frags.pcap-dist

test4.sh: 1qtcppadd.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) \
    dns.gold dns.pcap \
    frags.pcap \
    1qtcppadd.pcap
