MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS) $(libcrypto_CFLAGS)

pkglib_LTLIBRARIES = cryptopant.la
cryptopant_la_SOURCES = cryptopant.c
cryptopant_la_LDFLAGS = -module -avoid-version $(libcrypto_LIBS)

TESTS = test1.sh

EXTRA_DIST = $(TESTS) test1.gold keyfile
CLEANFILES = test1.out
