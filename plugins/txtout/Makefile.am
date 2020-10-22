MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = txtout.la
txtout_la_SOURCES = txtout.c
txtout_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh
EXTRA_DIST = $(TESTS)
CLEANFILES += test1.out *.pcap-dist

if ENABLE_GCOV
gcov-local:
	for src in $(txtout_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
