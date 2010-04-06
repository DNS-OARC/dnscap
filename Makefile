# $Id: Makefile,v 1.17 2008-04-22 00:37:44 vixie Exp $

#
# Copyright (c) 2007 by Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# tell GCC that we don't want unicode error messages
LANG= en_US

# set up defaults for configurables
HAVE_BINDLIB= 1
BINDLIB= -lbind
BINDCFLAGS= `PATH=/usr/local/bin:$$PATH isc-config.sh --cflags`
BINDLDFLAGS= `PATH=/usr/local/bin:$$PATH isc-config.sh --libs`
GCCWARN= -W -Wall -Werror -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
CWARN= ${GCCWARN}
PORTCFLAGS=
PORTLDFLAGS=
PORTLIBS=
PORTINCS=
PORTOBJ=

# uncomment these if you don't have bind9's libbind and its fp_nquery function
#HAVE_BINDLIB= 0
#BINDLIB= 
#BINDCFLAGS= -I/usr/local/include -I/usr/local/bind/include
#BINDLDFLAGS=

# uncomment these if you don't have GCC
#CWARN=

# uncomment these if you're building on HPUX.  see also:
#	http://devresource.hp.com/drc/resources/LPK/index.jsp
#PORTCFLAGS= -I/usr/local/hplx/include
#PORTLDFLAGS= -L/usr/local/hplx/lib
#PORTLIBS= -lhplx

# uncomment these if you're building on FreeBSD or where fp_nquery() is in libc
#PORTCFLAGS=
#PORTLDFLAGS=
#PORTLIBS=

# uncomment these if you're building on CentOS or many other versions of Linux
#CWARN=
#PORTLIBS= /usr/lib/libresolv.a
#BINDCFLAGS=-I/usr/local/include/bind
#BINDLDFLAGS=

# uncomment if you're building for Solaris 
#PORTOBJ=snprintf.o
#PORTINCS=snprintf.h
#PORTLIBS=-lrt -lmd5 -lsocket -lnsl -lresolv

ALL= dnscap dnscap.cat1

CDEBUG= -g -O
CFLAGS= ${CDEBUG} ${CWARN} -DHAVE_BINDLIB=${HAVE_BINDLIB} \
	${BINDCFLAGS} ${PORTCFLAGS}
LDFLAGS= ${BINDLDFLAGS} ${PORTLDFLAGS}
LDLIBS= -lpcap ${BINDLIB} ${PORTLIBS}

all: ${ALL}

install: all
	mkdir -p /usr/local/bin /usr/local/man/cat1
	if [ -f /usr/local/bin/dnscap ]; then \
		mv -f /usr/local/bin/dnscap \
			/usr/local/bin/dnscap.old; fi
	cp dnscap /usr/local/bin
	cp dnscap.cat1 /usr/local/man/cat1/dnscap.1

.c.o:
	${CC} ${CFLAGS} -c $<

DNSCAP_OBJ= dnscap.o dump_dns.o ${PORTOBJ}
dnscap: ${DNSCAP_OBJ} Makefile
	${CC} -o dnscap ${LDFLAGS} ${DNSCAP_OBJ} ${LDLIBS}

${DNSCAP_OBJ}: Makefile dnscap.c dump_dns.c dump_dns.h ${PORTINCS}

snprintf.h:
	wget -nc http://www.ijs.si/software/snprintf/snprintf_2.2.tar.gz
	wget -nc http://www.ijs.si/software/snprintf/snprintf_2.2.tar.gz.md5
	md5sum -c --status snprintf_2.2.tar.gz.md5 || true
	gunzip -c snprintf_2.2.tar.gz | tar -xf -
	${MAKE} -C snprintf_2.2 "COMPATIBILITY=-DNEED_ASPRINTF -DNEED_VASPRINTF"
	cp snprintf_2.2/snprintf.[ho] .

dnscap.cat1: dnscap.1
	nroff -mandoc dnscap.1 > dnscap.cat1

clean:; rm -f ${ALL} snprintf* *.o *.core *.orig all
