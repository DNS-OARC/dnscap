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


CC=gcc
CFLAGS=-Wall -g -O2 
LIBS=-ldl -lpcap -lresolv 
LDFLAGS=

prog=dnscap
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
datarootdir=${prefix}/share
datadir=${datarootdir}
mandir=${datarootdir}/man

SRCS=	${prog}.c \
	dump_dns.c \
	dump_dns.h \
	${NEED_SNPRINTF_H}

OBJS=	${prog}.o \
	dump_dns.o \
	${NEED_SNPRINTF_O}

all: ${prog} ${prog}.cat1

install: all
	install -d -m 755 ${bindir}
	if [ -f ${bindir}/${prog} ]; then \
		mv -f ${bindir}/${prog} ${bindir}/${prog}.old; fi
	install -m 755 ${prog} ${bindir}/
	install -d -m 755 ${mandir}
	install -d -m 755 ${mandir}/cat1
	install -m 644 ${prog}.cat1 ${mandir}/cat1/${prog}.1

.c.o:
	${CC} ${CFLAGS} -c $<

${prog}: ${OBJS} Makefile
	${CC} -o ${prog} ${LDFLAGS} ${OBJS} ${LIBS}

${OBJS}: Makefile ${SRCS}

snprintf_2.2:
	wget -nc http://www.ijs.si/software/snprintf/snprintf_2.2.tar.gz
	wget -nc http://www.ijs.si/software/snprintf/snprintf_2.2.tar.gz.md5
	md5sum -c --status snprintf_2.2.tar.gz.md5 || true
	gunzip -c snprintf_2.2.tar.gz | tar -xf -

snprintf.h: snprintf_2.2
	cd snprintf_2.2 && ${MAKE} "COMPATIBILITY=-DNEED_ASPRINTF -DNEED_VASPRINTF"
	cp snprintf_2.2/snprintf.[ho] .

${prog}.cat1: ${prog}.1
	nroff -mandoc ${prog}.1 > ${prog}.cat1

clean:; rm -f ${prog} ${prog}.cat1 snprintf.[ho] *.o *.core *.orig

distclean:: clean
	rm -f config.status
	rm -f config.log
	rm -rf autom4te.cache
	rm -f config.h
	rm -f Makefile
	rm -rf snprintf_2.2
