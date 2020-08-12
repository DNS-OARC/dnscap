MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = pcapdump.la
pcapdump_la_SOURCES = pcapdump.c
pcapdump_la_LDFLAGS = -module -avoid-version

if ENABLE_GCOV
gcov-local:
	for src in $(pcapdump_la_SOURCES); do \
	  gcov -o .libs -l -r -s "$(srcdir)" "$$src"; \
	done
endif
