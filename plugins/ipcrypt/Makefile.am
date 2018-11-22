MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = ipcrypt.la
ipcrypt_la_SOURCES = ipcrypt.c
ipcrypt_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh

EXTRA_DIST = $(TESTS) test1.gold
CLEANFILES = test1.out
