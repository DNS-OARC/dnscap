MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov *.pcap-dist

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    -I$(top_srcdir)/plugins/shared \
    $(SECCOMPFLAGS) $(libcrypto_CFLAGS)

pkglib_LTLIBRARIES = cryptopant.la
cryptopant_la_SOURCES = cryptopant.c
cryptopant_la_LDFLAGS = -module -avoid-version $(libcrypto_LIBS)

TESTS = test1.sh test2.sh test3.sh test4.sh

EXTRA_DIST = $(TESTS) test1.gold keyfile test2.gold test3.gold
CLEANFILES += test1.out test2.out test3.out test3.pcap.20161020.152301.075993 \
  test3.pcap.20181127.155200.414188

if ENABLE_GCOV
gcov-local:
	for src in $(cryptopant_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
