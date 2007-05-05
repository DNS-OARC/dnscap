LANG=en_US

ALL= dnscap dnscap.cat1

CDEBUG= -g -O
CWARN=-W -Wall -Werror -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
CFLAGS= ${CDEBUG} ${CWARN}

LDLIBS= -lpcap -lbind
LDFLAGS=

all: ${ALL}
	touch all

.c.o:
	@echo \(compile $< w/ ${CDEBUG}\) && \
		${CC} ${CFLAGS} \
		`PATH=/usr/local/bin:$$PATH isc-config.sh --cflags` \
		-c $<

DNSCAP_OBJ= dnscap.o
dnscap: ${DNSCAP_OBJ}
	${CC} -o dnscap ${LDFLAGS} \
		`PATH=/usr/local/bin:$$PATH isc-config.sh --libs` \
		${DNSCAP_OBJ} ${LDLIBS}

dnscap.cat1: dnscap.1
	nroff -mandoc dnscap.1 > dnscap.cat1

clean:; rm -f ${ALL} *.o *.core *.orig all
