ACLOCAL_AMFLAGS = -I m4 -I src/pcap-thread/m4

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in \
    $(srcdir)/src/config.h.in~ \
    $(srcdir)/configure

SUBDIRS = src plugins

dist_doc_DATA = README.md LICENSE CONTRIBUTORS

EXTRA_DIST = isc m4 .clang-format fmt.sh

test: check
