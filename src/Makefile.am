MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/config.h.in
CLEANFILES = dnscap.1 *.gcda *.gcno *.gcov

SUBDIRS = test

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(SECCOMPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(libcrypto_CFLAGS) \
  $(libldns_CFLAGS) \
  $(liblz4_CFLAGS) \
  $(libzstd_CFLAGS) \
  $(liblzma_CFLAGS)

EXTRA_DIST = dnscap.1.in

bin_PROGRAMS = dnscap

dnscap_SOURCES = args.c assert.c bpft.c daemon.c dnscap.c dump_cbor.c \
  dump_cds.c dump_dns.c dumper.c endpoint.c hashtbl.c iaddr.c log.c \
  network.c options.c pcaps.c sig.c tcpstate.c tcpreasm.c memzero.c \
  pcap-thread/pcap_thread.c pcap-thread/pcap_thread_ext_frag.c \
  ext/lookup3.c
dist_dnscap_SOURCES = args.h bpft.h daemon.h dnscap_common.h dnscap.h \
  dump_cbor.h dump_cds.h dump_dns.h dumper.h endpoint.h hashtbl.h iaddr.h \
  log.h network.h options.h pcaps.h sig.h tcpstate.h tcpreasm.h memzero.h \
  endian_compat.h \
  pcap-thread/pcap_thread.h pcap-thread/pcap_thread_ext_frag.h
dnscap_LDADD = $(PTHREAD_LIBS) $(libcrypto_LIBS) $(libldns_LIBS) \
  $(liblz4_LIBS) $(libzstd_LIBS) $(liblzma_LIBS)

man1_MANS = dnscap.1

dnscap.1: dnscap.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
        -e 's,[@]pkglibdir[@],$(pkglibdir),g' \
        < $(srcdir)/dnscap.1.in > dnscap.1

if ENABLE_GCOV
gcov-local:
	for src in $(dnscap_SOURCES); do \
	  gcov -l -r -s "$(srcdir)" "$$src"; \
	done
endif
