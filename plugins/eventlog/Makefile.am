MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov *.pcap-dist

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS) \
    $(libldns_CFLAGS)

pkglib_LTLIBRARIES = eventlog.la
eventlog_la_SOURCES = eventlog.c
eventlog_la_LDFLAGS = -module -avoid-version $(libldns_LIBS)

TESTS = test1.sh
EXTRA_DIST = $(TESTS)
CLEANFILES += test1.out

if ENABLE_GCOV
gcov-local:
	for src in $(eventlog_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
