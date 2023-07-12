MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov *.pcap-dist

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    -I$(top_srcdir)/plugins/shared \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = anonmask.la
anonmask_la_SOURCES = anonmask.c
anonmask_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh test2.sh test3.sh

EXTRA_DIST = $(TESTS) test1.gold test2.gold
CLEANFILES += test1.out test2.out

if ENABLE_GCOV
gcov-local:
	for src in $(anonmask_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
