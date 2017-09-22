MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = test*.log test*.trs \
    *.pcap-dist \
    dns.out \
    no-layers.out layers.out

TESTS = test1.sh test2.sh

test1.sh: dns.pcap-dist

test2.sh: dns.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) \
    dns.gold \
    dns.pcap
