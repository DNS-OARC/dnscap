MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov *.pcap-dist

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS) \
    $(libldns_CFLAGS)

pkglib_LTLIBRARIES = rssm.la
rssm_la_SOURCES = rssm.c
rssm_la_LDFLAGS = -module -avoid-version $(libldns_LIBS)
TESTS = test1.sh test2.sh test3.sh test4.sh test5.sh
EXTRA_DIST = $(TESTS) test1.gold test2.gold dnscap-rssm-rssac002.1.in \
  test3.gold test5.gold
dist_bin_SCRIPTS = dnscap-rssm-rssac002
man1_MANS = dnscap-rssm-rssac002.1
CLEANFILES += test1.20161020.152301.075993 test2.out $(man1_MANS) \
  test3.20181127.155200.414188 test4.*20161020.152301.075993 \
  test5.20180110.112241.543825

if ENABLE_GCOV
gcov-local:
	for src in $(rssm_la_SOURCES) $(nodist_rssm_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif

dnscap-rssm-rssac002.1: dnscap-rssm-rssac002.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
        < $(srcdir)/dnscap-rssm-rssac002.1.in > dnscap-rssm-rssac002.1
