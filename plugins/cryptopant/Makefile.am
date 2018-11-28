MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS) $(libcrypto_CFLAGS)

pkglib_LTLIBRARIES = cryptopant.la
cryptopant_la_SOURCES = cryptopant.c
cryptopant_la_LDFLAGS = -module -avoid-version $(libcrypto_LIBS)

TESTS = test1.sh test2.sh test3.sh

EXTRA_DIST = $(TESTS) test1.gold keyfile test2.gold test3.gold
CLEANFILES = test1.out test2.out test3.out test3.pcap.20161020.152301.075993 \
  test3.pcap.20181127.155200.414188
