MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

if HAVE_LDNS
pkglib_LTLIBRARIES = rzkeychange.la
rzkeychange_la_SOURCES = rzkeychange.c
rzkeychange_la_LDFLAGS = -module -avoid-version $(LIBRARY_VERSION)

TESTS = test1.sh
EXTRA_DIST = $(TESTS)
CLEANFILES += *.pcap-dist

if ENABLE_GCOV
gcov-local:
	for src in $(rzkeychange_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
endif
