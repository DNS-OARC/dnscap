MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = test*.log test*.trs \
    dns.out \
    dns.pcap.dist

TESTS = test1.sh

test1.sh: dns.pcap.dist

dns.pcap.dist: dns.pcap
	ln -s "$(srcdir)/dns.pcap" dns.pcap.dist

EXTRA_DIST = $(TESTS) \
    dns.gold \
    dns.pcap
