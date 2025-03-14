MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov *.pcap-dist test1.out

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = asudp.la
asudp_la_SOURCES = asudp.c
asudp_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh
EXTRA_DIST = $(TESTS) test1.gold

if ENABLE_GCOV
gcov-local:
	for src in $(asudp_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
