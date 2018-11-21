MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = anonmask.la
anonmask_la_SOURCES = anonmask.c
anonmask_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh

test1.sh: dns.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) dns.pcap test1.gold
CLEANFILES = test1.out
