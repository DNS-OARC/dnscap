MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = anonzero.la
anonzero_la_SOURCES = anonzero.c
anonzero_la_LDFLAGS = -module -avoid-version
