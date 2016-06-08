MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = dnscap.1

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir) \
    $(SECCOMPFLAGS)

EXTRA_DIST = dnscap.1.in

bin_PROGRAMS = dnscap
dnscap_SOURCES = dnscap.c \
    dump_dns.c
dist_dnscap_SOURCES = dnscap_common.h \
    dump_dns.h

man1_MANS = dnscap.1

dnscap.1: dnscap.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
        < $(srcdir)/dnscap.1.in > dnscap.1
