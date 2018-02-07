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
TESTS = test1.sh test2.sh
EXTRA_DIST = $(TESTS) test1.gold test2.gold dnscap-rssm-rssac002.1.in
dist_bin_SCRIPTS = dnscap-rssm-rssac002
man1_MANS = dnscap-rssm-rssac002.1
CLEANFILES += test2.out $(man1_MANS)
endif

hashtbl.c: $(top_srcdir)/src/hashtbl.c
	cp $(top_srcdir)/src/hashtbl.c ./

$(srcdir)/hashtbl.c: $(top_srcdir)/src/hashtbl.c
	cp $(top_srcdir)/src/hashtbl.c $(srcdir)/

dnscap-rssm-rssac002.1: dnscap-rssm-rssac002.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
        < $(srcdir)/dnscap-rssm-rssac002.1.in > dnscap-rssm-rssac002.1
