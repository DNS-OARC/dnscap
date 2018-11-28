MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = anonmask.la
anonmask_la_SOURCES = anonmask.c
anonmask_la_LDFLAGS = -module -avoid-version

TESTS = test1.sh test2.sh

EXTRA_DIST = $(TESTS) test1.gold test2.gold
CLEANFILES = test1.out test2.out
