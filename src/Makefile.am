MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = dnscap.1

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir) \
    $(SECCOMPFLAGS) \
    $(PTHREAD_CFLAGS)

EXTRA_DIST = dnscap.1.in

bin_PROGRAMS = dnscap

dnscap_SOURCES = dnscap.c \
    dump_dns.c \
    dump_cbor.c dump_cds.c \
    pcap-thread/pcap_thread.c \
    options.c hashtbl.c
dist_dnscap_SOURCES = dnscap.h \
    dnscap_common.h \
    dump_dns.h \
    dump_cbor.h dump_cds.h \
    pcap-thread/pcap_thread.h \
    options.h hashtbl.h
dnscap_LDADD = $(PTHREAD_LIBS)

man1_MANS = dnscap.1

dnscap.1: dnscap.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
        < $(srcdir)/dnscap.1.in > dnscap.1
