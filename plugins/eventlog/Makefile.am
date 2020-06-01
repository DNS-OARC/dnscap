MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = eventlog.la
eventlog_la_SOURCES = eventlog.c
eventlog_la_LDFLAGS = -module -avoid-version
