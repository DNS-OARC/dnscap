MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

if LDNS
pkglib_LTLIBRARIES = rssm.la
rssm_la_SOURCES = rssm.c hashtbl.c
dist_rssm_la_SOURCES = hashtbl.h
rssm_la_LDFLAGS = -module -version-info $(LIBRARY_VERSION)
rssm_la_LIBADD = -lldns
endif
