# tell GCC that we don't want unicode error messages
LANG= en_US

# set up defaults for configurables
HAVE_BINDLIB= 1
BINDLIB= -lbind
BINDCFLAGS= `PATH=/usr/local/bin:$$PATH isc-config.sh --cflags`
BINDLDFLAGS= `PATH=/usr/local/bin:$$PATH isc-config.sh --libs`
GCCWARN= -W -Wall -Werror -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
CWARN= ${GCCWARN}

# uncomment these if you don't have bind9's libbind and its fp_nquery function
#HAVE_BINDLIB= 0
#BINDLIB=
#BINDCFLAGS= -I/usr/local/include -I/usr/local/bind/include
#BINDLDFLAGS=

# uncomment these if you don't have GCC
#CWARN=

ALL= dnscap dnscap.cat1

CDEBUG= -g -O
CFLAGS= ${CDEBUG} ${CWARN} -DHAVE_BINDLIB=${HAVE_BINDLIB} ${BINDCFLAGS}
LDFLAGS= ${BINDLDFLAGS}
LDLIBS= -lpcap ${BINDLIB}

all: ${ALL}
	rm -f all; touch all

.c.o:
	@echo \(compile $< w/ ${CDEBUG}\) && ${CC} ${CFLAGS} -c $<

DNSCAP_OBJ= dnscap.o
dnscap: ${DNSCAP_OBJ} Makefile
	@echo \(link $< w/ ${LDLIBS}\) && \
		${CC} -o dnscap ${LDFLAGS} ${DNSCAP_OBJ} ${LDLIBS}

${DNSCAP_OBJ}: Makefile

dnscap.cat1: dnscap.1
	nroff -mandoc dnscap.1 > dnscap.cat1

clean:; rm -f ${ALL} *.o *.core *.orig all
