MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = $(srcdir)/hashtbl.c \
    hashtbl.c

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

if HAVE_LDNS
pkglib_LTLIBRARIES = rssm.la
rssm_la_SOURCES = rssm.c
nodist_rssm_la_SOURCES = hashtbl.c
BUILT_SOURCES = hashtbl.c
rssm_la_LDFLAGS = -module -avoid-version
endif

hashtbl.c: $(top_srcdir)/src/hashtbl.c
	cp $(top_srcdir)/src/hashtbl.c ./

$(srcdir)/hashtbl.c: $(top_srcdir)/src/hashtbl.c
	cp $(top_srcdir)/src/hashtbl.c $(srcdir)/
