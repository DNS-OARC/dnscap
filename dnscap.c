/* dnscap - DNS capture utility
 *
 * Paul Vixie (original) and Duane Wessels (IPv6 port)
 */

#ifndef lint
static const char rcsid[] = "$Id: dnscap.c,v 1.11 2007-05-16 22:55:21 vixie Exp $";
static const char copyright[] =
	"Copyright (c) 2007 by Internet Systems Consortium, Inc. (\"ISC\")";
#endif

/*
 * Copyright (c) 2007 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifdef __linux__
# define __FAVOR_BSD
# define __USE_GNU
# define _GNU_SOURCE
# include <net/ethernet.h>
#endif

#ifdef __FreeBSD__
# include <net/ethernet.h>
#endif

#ifdef __NetBSD__
# include <net/ethertypes.h>
# include <net/if.h>
# include <net/if_ether.h>
#endif 

#ifdef __OpenBSD__
# include <net/ethertypes.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/in_var.h>
# include <netinet/if_ether.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pcap.h>
#include <regex.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/list.h>

/* Constants. */

#ifndef IPV6_VERSION
# define IPV6_VERSION		0x60
#endif
#ifndef IPV6_VERSION_MASK
# define IPV6_VERSION_MASK	0xf0
#endif

#define UDP10_QR_MASK	0x80
#define UDP10_QR_SHIFT	7
#define UDP10_OP_MASK	0x78
#define UDP10_OP_SHIFT	3
#define UDP10_AA_MASK	0x04
#define UDP10_AA_SHIFT	2
#define UDP10_TC_MASK	0x02
#define UDP10_TC_SHIFT	1
#define UDP10_RD_MASK	0x01
#define UDP10_RD_SHIFT	0

#define UDP11_RC_MASK	0x0f
#define UDP11_RC_SHIFT	0

#define MSG_QUERY	0x0001
#define MSG_UPDATE	0x0002
#define MSG_INITIATE	0x0004
#define MSG_RESPONSE	0x0008
#define MSG_ERROR	0x0010

#define END_INITIATOR	0x0001
#define END_RESPONDER	0x0002

#define HIDE_INET	0x7f7f7f7f
#define HIDE_INET6	"\177\177\177\177\177\177\177\177" \
			"\177\177\177\177\177\177\177\177"
#define HIDE_UDP	54321

#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN	0x8100
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#define DAY		(24*60*60)
#define THOUSAND	1000
#define MILLION		(THOUSAND*THOUSAND)
#define BILLION		(THOUSAND*MILLION)
#define MAX_VLAN	4095
#define DNS_PORT	53
#define TO_MS		50
#define SNAPLEN		65536
#define TRUE		1
#define FALSE		0
#define REGEX_CFLAGS	(REG_EXTENDED|REG_ICASE|REG_NOSUB|REG_NEWLINE)

/* Data structures. */

typedef struct {
	int			af;
	union {
		struct in_addr		a4;
		struct in6_addr		a6;
	} u;
} iaddr;

struct endpoint {
	ISC_LINK(struct endpoint)  link;
	iaddr			ia;
};
typedef struct endpoint *endpoint_ptr;
typedef ISC_LIST(struct endpoint) endpoint_list;

struct mypcap {
	ISC_LINK(struct mypcap)	link;
	const char *		name;
	int			fdes;
	pcap_t *		pcap;
	int			dlt;
};
typedef struct mypcap *mypcap_ptr;
typedef ISC_LIST(struct mypcap) mypcap_list;

struct vlan {
	ISC_LINK(struct vlan)	link;
	unsigned		vlan;
};
typedef struct vlan *vlan_ptr;
typedef ISC_LIST(struct vlan) vlan_list;

struct text {
	ISC_LINK(struct text)	link;
	size_t			len;
	char *			text;
};
typedef struct text *text_ptr;
typedef ISC_LIST(struct text) text_list;
#define text_size(len) (sizeof(struct text) + len)

struct myregex {
	ISC_LINK(struct myregex)  link;
	regex_t			reg;
};
typedef struct myregex *myregex_ptr;
typedef ISC_LIST(struct myregex) myregex_list;

/* Forward. */

static void setsig(int, int);
static void usage(const char *) __attribute__((noreturn));
static void help_1(void);
static void help_2(void);
static void parse_args(int, char *[]);
static void endpoint_arg(endpoint_list *, const char *);
static void endpoint_add(endpoint_list *, iaddr);
static void prepare_bpft(void);
static const char *ia_str(iaddr);
static int ep_present(const endpoint_list *, iaddr);
static size_t text_add(text_list *, const char *, ...);
static void open_pcaps(void);
static void poll_pcaps(void);
static void close_pcaps(void);
static void live_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static int dumper_open(struct timeval);
static int dumper_close(void);
static void sigclose(int);
static void sigbreak(int);
static uint16_t in_checksum(const u_char *, size_t);

/* Private data. */

static const char *ProgramName = "amnesia";
static int verbose = FALSE;
static int flush = FALSE;
static vlan_list vlans;
static unsigned msg_wanted = MSG_QUERY|MSG_INITIATE|MSG_RESPONSE;
static unsigned end_hide = 0U;
static endpoint_list initiators;
static endpoint_list responders;
static myregex_list myregexes;
static mypcap_list mypcaps;
static mypcap_ptr pcap_offline = NULL;
static const char *dump_base = NULL;
static enum {nowhere, to_stdout, to_file} dump_type = nowhere;
static const char *kick_cmd = NULL;
static unsigned limit_seconds = DAY;
static unsigned limit_packets = BILLION;
static fd_set mypcap_fdset;
static int pcap_maxfd;
static pcap_t *pcap_dead;
static int linktype;
static pcap_dumper_t *dumper;
static time_t dumpstart;
static unsigned msgcount;
static char *dumpname, *dumpnamepart;
static char *bpft;
static unsigned dns_port = DNS_PORT;
static int promisc = FALSE;
static char errbuf[PCAP_ERRBUF_SIZE];
static int v6bug = FALSE;
static int dig_it = FALSE;
static int main_exit = FALSE;

/* Public. */

int
main(int argc, char *argv[]) {
	parse_args(argc, argv);
	prepare_bpft();
	open_pcaps();
	setsig(SIGHUP, TRUE);
	setsig(SIGINT, TRUE);
	setsig(SIGALRM, FALSE);
	setsig(SIGTERM, TRUE);
	if (dump_type == nowhere)
		dumpstart = time(NULL);
	while (!main_exit)
		poll_pcaps();
	close_pcaps();
	if (dumper != NULL)
		(void) dumper_close();
	exit(0);
}

/* Private. */

static void
setsig(int sig, int oneshot) {
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	if (oneshot) {
		sa.sa_handler = sigbreak;
		sa.sa_flags = SA_RESETHAND;
	} else {
		sa.sa_handler = sigclose;
		sa.sa_flags = SA_RESTART;
	}
	if (sigaction(sig, &sa, NULL) < 0) {
		perror("sigaction");
		exit(1);
	}
}

static void
usage(const char *msg) {
	fprintf(stderr, "%s: usage error: %s\n", ProgramName, msg);
	fprintf(stderr, "\n");
	help_1();
	fprintf(stderr,
		"\nnote: the -? or -\\? option will display full help text\n");
	exit(1);
}

static void
help_1(void) {
	fprintf(stderr,
		"usage: %s\n"
		"\t[-avfg6] [-i <if>]+ [-o <file>] [-l <vlan>]+ [-p <port>]\n"
		"\t[-m [quire]] [-h [ir]] [-q <host>]+ [-r <host>]+\n"
		"\t[-d <base> [-k <cmd>]] [-t <lim>] [-c <lim>] [-x <pat>]+\n",
		ProgramName);
}

static void
help_2(void) {
	help_1();
	fprintf(stderr,
		"\noptions:\n"
		"\t-a         collect packets promiscuously\n"
		"\t-v         be verbose to stderr\n"
		"\t-f         flush output on every packet\n"
		"\t-g         dump packets dig-style on stderr\n"
		"\t-6         compensate for PCAP/BPF IPv6 bug\n"
		"\t-i <if>    pcap interface(s)\n"
		"\t-o <file>  pcap offline file\n"
		"\t-l <vlan>  pcap vlan(s)\n"
		"\t-p <port>  dns port (default: 53)\n"
		"\t-m [quire] query, update, initiate, response, err\n"
		"\t-h [ir]    hide initiators and/or responders\n"
		"\t-q <host>  initiator(s)\n"
		"\t-r <host>  responder(s)\n"
		"\t-d <base>  dump to <base>.<timesec>.<timeusec>\n"
		"\t-k <cmd>   kick off <cmd> when each dump closes\n"
		"\t-t <lim>   close dump or exit every <lim> secs\n"
		"\t-c <lim>   close dump or exit every <lim> pkts\n"
		"\t-x <pat>   display messages matching regex <pat>\n");
}

static void
parse_args(int argc, char *argv[]) {
#ifdef HAVE_BINDLIB
	myregex_ptr myregex;
#endif
	mypcap_ptr mypcap;
	vlan_ptr vlan;
	int i, ch;
	char *p;

	if ((p = strrchr(argv[0], '/')) == NULL)
		ProgramName = argv[0];
	else
		ProgramName = p+1;
	ISC_LIST_INIT(vlans);
	ISC_LIST_INIT(mypcaps);
	ISC_LIST_INIT(initiators);
	ISC_LIST_INIT(responders);
	while ((ch = getopt(argc, argv,
			    "avfg6?i:o:l:p:m:h:q:r:d:k:t:c:x:")
		) != EOF)
	{
		switch (ch) {
		case 'a':
			promisc = TRUE;
			break;
		case 'v':
			verbose = TRUE;
			break;
		case 'f':
			flush = TRUE;
			break;
		case 'g':
#if HAVE_BINDLIB
			dig_it = TRUE;
#else
			usage("-g option is disabled due to lack of libbind");
#endif
			break;
		case '6':
			v6bug = TRUE;
			break;
		case '?':
			help_2();
			exit(0);
			break;
		case 'i':
			if (pcap_offline != NULL)
				usage("-i makes no sense after -o");
			mypcap = malloc(sizeof *mypcap);
			assert(mypcap != NULL);
			ISC_LINK_INIT(mypcap, link);
			mypcap->name = strdup(optarg);
			assert(mypcap->name != NULL);
			mypcap->fdes = -1;
			ISC_LIST_APPEND(mypcaps, mypcap, link);
			break;
		case 'o':
			if (!ISC_LIST_EMPTY(mypcaps))
				usage("-o makes no sense after -i");
			pcap_offline = malloc(sizeof *pcap_offline);
			assert(pcap_offline != NULL);
			ISC_LINK_INIT(pcap_offline, link);
			pcap_offline->name = strdup(optarg);
			assert(pcap_offline->name != NULL);
			pcap_offline->fdes = -1;
			ISC_LIST_APPEND(mypcaps, pcap_offline, link);
			break;
		case 'l':
			i = atoi(optarg);
			if (i < 1 || i > MAX_VLAN)
				usage("vlan must be an integer 1..4095");
			vlan = malloc(sizeof *vlan);
			assert(vlan != NULL);
			ISC_LINK_INIT(vlan, link);
			vlan->vlan = i;
			ISC_LIST_APPEND(vlans, vlan, link);
			break;
		case 'p':
			i = atoi(optarg);
			if (i < 1 || i > 65535)
				usage("port must be an integer 1..65535");
			dns_port = i;
			break;
		case 'm':
			i = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'q': i |= MSG_QUERY; break;
				case 'u': i |= MSG_UPDATE; break;
				case 'i': i |= MSG_INITIATE; break;
				case 'r': i |= MSG_RESPONSE; break;
				case 'e': i |= MSG_ERROR; break;
				default: usage("-m takes only [qure]");
				}
			msg_wanted = i;
			break;
		case 'h':
			i = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'i': i |= END_INITIATOR; break;
				case 'r': i |= END_RESPONDER; break;
				default: usage("-h takes only [ir]");
				}
			end_hide = i;
			break;
		case 'q':
			endpoint_arg(&initiators, optarg);
			break;
		case 'r':
			endpoint_arg(&responders, optarg);
			break;
		case 'd':
			dump_base = optarg;
			if (strcmp(optarg, "-") == 0)
				dump_type = to_stdout;
			else
				dump_type = to_file;
			break;
		case 'k':
			if (dump_type != to_file)
				usage("-k depends on -d"
				      " (note: can't be stdout)");
			kick_cmd = optarg;
			break;
		case 't':
			i = atoi(optarg);
			if (i == 0 || i > DAY)
				usage("-t argument is out of range");
			limit_seconds = i;
			break;
		case 'c':
			i = atoi(optarg);
			if (i == 0 || i > BILLION)
				usage("-c argument is out of range");
			limit_packets = i;
			break;
		case 'x':
#if HAVE_BINDLIB
			myregex = malloc(sizeof *myregex);
			assert(myregex != NULL);
			ISC_LINK_INIT(myregex, link);
			i = regcomp(&myregex->reg, optarg, REGEX_CFLAGS);
			if (i != 0) {
				regerror(i, &myregex->reg,
					 errbuf, sizeof errbuf);
				usage(errbuf);
			}
			ISC_LIST_APPEND(myregexes, myregex, link);
			break;
#else
			usage("-x option is disabled due to lack of libbind");
#endif
		default:
			usage("unrecognized command line option");
		}
	}
	assert(msg_wanted != 0U);
	if (dump_type == nowhere && !dig_it)
		usage("without -d or -g, there would be no output");
	if (verbose) {
		endpoint_ptr ep;
		const char *sep;

		fprintf(stderr, "%s: msg %c%c%c%c%c, hide %c%c, t %d, c %d\n",
			ProgramName,
			(msg_wanted & MSG_QUERY) != 0 ? 'Q' : '.',
			(msg_wanted & MSG_UPDATE) != 0 ? 'U' : '.',
			(msg_wanted & MSG_INITIATE) != 0 ? 'I' : '.',
			(msg_wanted & MSG_RESPONSE) != 0 ? 'R' : '.',
			(msg_wanted & MSG_ERROR) != 0 ? 'E' : '.',
			(end_hide & END_INITIATOR) != 0 ? 'I' : '.',
			(end_hide & END_RESPONDER) != 0 ? 'R' : '.',
			limit_seconds, limit_packets);
		sep = "\tinit";
		for (ep = ISC_LIST_HEAD(initiators);
		     ep != NULL;
		     ep = ISC_LIST_NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!ISC_LIST_EMPTY(initiators))
			fprintf(stderr, "\n");
		sep = "\tresp";
		for (ep = ISC_LIST_HEAD(responders);
		     ep != NULL;
		     ep = ISC_LIST_NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!ISC_LIST_EMPTY(responders))
			fprintf(stderr, "\n");
	}
	if (ISC_LIST_EMPTY(mypcaps)) {
		const char *name;
#ifdef __linux__
		name = NULL;	/* "all interfaces" */
#else
		name = pcap_lookupdev(errbuf);
		if (name == NULL) {
			fprintf(stderr, "%s: pcap_lookupdev: %s\n",
				ProgramName, errbuf);
			exit(1);
		}
#endif
		mypcap = malloc(sizeof *mypcap);
		assert(mypcap != NULL);
		ISC_LINK_INIT(mypcap, link);
		mypcap->name = name;
		mypcap->fdes = -1;
		ISC_LIST_APPEND(mypcaps, mypcap, link);
	}
}

static void
endpoint_arg(endpoint_list *list, const char *arg) {
	struct addrinfo *ai;
	iaddr ia;

	if (inet_pton(AF_INET6, arg, &ia.u.a6) > 0) {
		ia.af = AF_INET6;
		endpoint_add(list, ia);
	} else if (inet_pton(AF_INET, arg, &ia.u.a4) > 0) {
		ia.af = AF_INET;
		endpoint_add(list, ia);
	} else if (getaddrinfo(arg, NULL, NULL, &ai) == 0) {
		struct addrinfo *a;

		for (a = ai; a != NULL; a = a->ai_next) {
			if (a->ai_socktype != SOCK_DGRAM)
				continue;
			switch (a->ai_family) {
			case PF_INET:
				ia.af = AF_INET;
				ia.u.a4 = ((struct sockaddr_in *)a->ai_addr)
					->sin_addr;
				break;
			case PF_INET6:
				ia.af = AF_INET6;
				ia.u.a6 = ((struct sockaddr_in6 *)a->ai_addr)
					->sin6_addr;
				break;
			default:
				continue;
			}
			endpoint_add(list, ia);
		}
		freeaddrinfo(ai);
	} else
		usage("invalid host address");
}

static void
endpoint_add(endpoint_list *list, iaddr ia) {
	endpoint_ptr ep;

	ep = malloc(sizeof *ep);
	assert(ep != NULL);
	ISC_LINK_INIT(ep, link);
	ep->ia = ia;
	ISC_LIST_APPEND(*list, ep, link);
}

static void
prepare_bpft(void) {
	unsigned udp10_mbs, udp10_mbc, udp11_mbs, udp11_mbc;
	text_list bpfl;
	text_ptr text;
	size_t len;

	/* Prepare the must-be-set and must-be-clear tests. */
	udp10_mbs = udp10_mbc = udp11_mbs = udp11_mbc = 0U;
	if ((msg_wanted & MSG_INITIATE) != 0) {
		if ((msg_wanted & MSG_RESPONSE) == 0)
			udp10_mbc |= UDP10_QR_MASK;
	} else if ((msg_wanted & MSG_RESPONSE) != 0) {
		udp10_mbs |= UDP10_QR_MASK;
	}
	if ((msg_wanted & MSG_UPDATE) != 0) {
		if ((msg_wanted & MSG_QUERY) == 0)
			udp10_mbs |= (ns_o_update << UDP10_OP_SHIFT);
	} else if ((msg_wanted & MSG_QUERY) != 0) {
		udp10_mbc |= UDP10_OP_MASK;
	}
	if ((msg_wanted & MSG_ERROR) == 0) {
		udp10_mbc |= UDP10_TC_MASK;
		udp11_mbc |= UDP11_RC_MASK;
	}

	/* Make a BPF program to do early course kernel-level filtering. */
	ISC_LIST_INIT(bpfl);
	len = 0;
	len += text_add(&bpfl, "udp port %d", dns_port);
	if (!ISC_LIST_EMPTY(vlans))
		len += text_add(&bpfl, " and vlan");
	if (!v6bug) {
		if (udp10_mbc != 0)
			len += text_add(&bpfl, " and udp[10] & 0x%x = 0",
					udp10_mbc);
		if (udp10_mbs != 0)
			len += text_add(&bpfl, " and udp[10] & 0x%x = 0x%x",
					udp10_mbs, udp10_mbs);
		if (udp11_mbc != 0)
			len += text_add(&bpfl, " and udp[11] & 0x%x = 0",
					udp11_mbc);
		if (udp11_mbs != 0)
			len += text_add(&bpfl, " and udp[11] & 0x%x = 0x%x",
					udp11_mbs, udp11_mbs);
	}
	if (!ISC_LIST_EMPTY(initiators) && !ISC_LIST_EMPTY(responders)) {
		const char *or = "or", *lp = "(", *sep;
		endpoint_ptr ep;

		len += text_add(&bpfl, " and host");
		sep = lp;
		for (ep = ISC_LIST_HEAD(initiators);
		     ep != NULL;
		     ep = ISC_LIST_NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		for (ep = ISC_LIST_HEAD(responders);
		     ep != NULL;
		     ep = ISC_LIST_NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		len += text_add(&bpfl, " )");
	}
	bpft = malloc(len + 1);
	assert(bpft != NULL);
	bpft[0] = '\0';
	for (text = ISC_LIST_HEAD(bpfl);
	     text != NULL;
	     text = ISC_LIST_NEXT(text, link))
		strcat(bpft, text->text);
	if (verbose)
		fprintf(stderr, "%s: \"%s\"\n", ProgramName, bpft);
}

static const char *
ia_str(iaddr ia) {
	static char ret[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

	(void) inet_ntop(ia.af, &ia.u, ret, sizeof ret);
	return (ret);
}

static int
ep_present(const endpoint_list *list, iaddr ia) {
	endpoint_ptr ep;

	for (ep = ISC_LIST_HEAD(*list);
	     ep != NULL;
	     ep = ISC_LIST_NEXT(ep, link))
		if (ia.af == ep->ia.af)
			switch (ia.af) {
			case AF_INET:
				if (ia.u.a4.s_addr == ep->ia.u.a4.s_addr)
					return (TRUE);
				break;
			case AF_INET6:
				if (memcmp(&ia.u.a6, &ep->ia.u.a6,
					   sizeof ia.u.a6) == 0)
					return (TRUE);
				break;
			default:
				break;
			}
	return (FALSE);
}

static size_t
text_add(text_list *list, const char *fmt, ...) {
	text_ptr text;
	va_list ap;
	int len;

	text = malloc(sizeof *text);
	assert(text != NULL);
	ISC_LINK_INIT(text, link);
	va_start(ap, fmt);
	len = vasprintf(&text->text, fmt, ap);
	assert(len >= 0);
	va_end(ap);
	ISC_LIST_APPEND(*list, text, link);
	return (len);
}

static void
open_pcaps(void) {
	mypcap_ptr mypcap;

	assert(!ISC_LIST_EMPTY(mypcaps));
	linktype = -1;
	FD_ZERO(&mypcap_fdset);
	pcap_maxfd = 0;
	for (mypcap = ISC_LIST_HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = ISC_LIST_NEXT(mypcap, link))
	{
		struct bpf_program bpfp;

		errbuf[0] = '\0';
		if (pcap_offline == NULL)
			mypcap->pcap = pcap_open_live(mypcap->name, SNAPLEN,
						      promisc, TO_MS, errbuf);
		else
			mypcap->pcap = pcap_open_offline(mypcap->name, errbuf);
		if (mypcap->pcap == NULL) {
			fprintf(stderr, "%s: pcap open: %s\n",
				ProgramName, errbuf);
			exit(1);
		}
		if (errbuf[0] != '\0')
			fprintf(stderr, "%s: pcap warning: %s",
				ProgramName, errbuf);
		mypcap->dlt = pcap_datalink(mypcap->pcap);
		if (linktype == -1)
			linktype = mypcap->dlt;
		else if (linktype != mypcap->dlt)
			linktype = DLT_LOOP;
		mypcap->fdes = pcap_get_selectable_fd(mypcap->pcap);
		if (pcap_offline == NULL)
			if (pcap_setnonblock(mypcap->pcap, TRUE, errbuf) < 0) {
				fprintf(stderr, "%s: pcap_setnonblock: %s\n",
					ProgramName, errbuf);
				exit(1);
			}
		FD_SET(mypcap->fdes, &mypcap_fdset);
		if (mypcap->fdes > pcap_maxfd)
			pcap_maxfd = mypcap->fdes;
		if (pcap_compile(mypcap->pcap, &bpfp, bpft, TRUE, 0) < 0 ||
		    pcap_setfilter(mypcap->pcap, &bpfp) < 0) {
			fprintf(stderr, "%s: pcap error: %s\n",
				ProgramName, pcap_geterr(mypcap->pcap));
			exit(1);
		}
		pcap_freecode(&bpfp);
	}
	assert(linktype != -1);
	pcap_dead = pcap_open_dead(linktype, SNAPLEN);
}

static void
poll_pcaps(void) {
	mypcap_ptr mypcap;
	fd_set readfds;
	int n;

	do {
		readfds = mypcap_fdset;
		n = select(pcap_maxfd+1, &readfds, NULL, NULL, NULL);
	} while (n < 0 && errno == EINTR && !main_exit);
	if (n < 0) {
		if (errno != EINTR)
			perror("select");
		main_exit = TRUE;
		return;
	}
	/* Poll them all. */
	for (mypcap = ISC_LIST_HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = ISC_LIST_NEXT(mypcap, link))
	{
		n = pcap_dispatch(mypcap->pcap, -1, live_packet,
				  (u_char *)mypcap);
		if (n == -1)
			fprintf(stderr, "%s: pcap_dispatch: %s\n",
				ProgramName, errbuf);
		if (n < 0 || pcap_offline != NULL) {
			main_exit = TRUE;
			return;
		}
	}
}

static void
close_pcaps(void) {
	mypcap_ptr mypcap;

	for (mypcap = ISC_LIST_HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = ISC_LIST_NEXT(mypcap, link))
		pcap_close(mypcap->pcap);
	pcap_close(pcap_dead);
}

static void
live_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *opkt) {
	u_char pkt_copy[SNAPLEN+NS_INT32SZ],
		*pkt = pkt_copy+NS_INT32SZ,
		*netptr, *dlptr;
	mypcap_ptr mypcap = (mypcap_ptr) user;
	iaddr from, to, initiator, responder;
	unsigned etype, proto, sport, dport;
	size_t len = hdr->caplen;
	struct ip6_hdr *ipv6;
	struct udphdr *udp;
	unsigned vlan, pf;
	struct ip *ip;
	HEADER dns;

	/* Sometimes pcap_breakloop() stutters. */
	if (main_exit)
		return;

	/* If ever SNAPLEN wasn't big enough, we have no recourse. */
	if (hdr->len != hdr->caplen)
		return;

	/* Make a writable copy of the packet and use that copy from now on. */
	memcpy(pkt, opkt, len);

	/* Data link. */
	vlan = 0;
	dlptr = pkt;
	switch (mypcap->dlt) {
	case DLT_NULL: {
		uint32_t x;

		if (len < NS_INT32SZ)
			return;
		x = *(const uint32_t *)pkt;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		pkt += NS_INT32SZ;
		len -= NS_INT32SZ;
		break;
	    }
	case DLT_LOOP: {
		uint32_t x;

		if (len < NS_INT32SZ)
			return;
		NS_GET32(x, pkt);
		len -= NS_INT32SZ;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		break;
	    }
	case DLT_EN10MB: {
		const struct ether_header *ether;

		if (len < ETHER_HDR_LEN)
			return;
		ether = (void *) pkt;
		etype = ntohs(ether->ether_type);
		pkt += ETHER_HDR_LEN;
		len -= ETHER_HDR_LEN;
		if (etype == ETHERTYPE_VLAN) {
			if (len < 4)
				return;
			vlan = ntohs(*(const uint16_t *) pkt);
			pkt += 2;
			len -= 2;
			if (vlan < 1 || vlan > MAX_VLAN)
				return;
			etype = ntohs(*(const uint16_t *) pkt);
			pkt += 2;
			len -= 2;
		}
		break;
	    }
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL: {
		if (len < 16)
			return;
		etype = ntohs(*(const uint16_t *) &pkt[14]);
		pkt += 16;
		len -= 16;
		break;
	    }
#endif
	default:
		return;
	}

	/* Network. */
	ip = NULL;
	ipv6 = NULL;
	netptr = pkt;
	switch (etype) {
	case ETHERTYPE_IP: {
		unsigned offset;

		if (len < sizeof *ip)
			return;
		ip = (void *) pkt;
		if (ip->ip_v != IPVERSION)
			return;
		proto = ip->ip_p;
		memset(&from, 0, sizeof from);
		from.af = AF_INET;
		from.u.a4 = ip->ip_src;
		memset(&to, 0, sizeof to);
		to.af = AF_INET;
		to.u.a4 = ip->ip_dst;
		offset = ip->ip_hl << 2;
		if (len <= offset)
			return;
		pkt += offset;
		len -= offset;
		pf = PF_INET;
		break;
	    }
	case ETHERTYPE_IPV6: {
		uint16_t payload_len;
		uint8_t nexthdr;
		unsigned offset;

		if (len < sizeof *ipv6)
			return;
		ipv6 = (void *) pkt;
		if ((ipv6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return;

		nexthdr = ipv6->ip6_nxt;
		offset = sizeof(struct ip6_hdr);
		payload_len = ntohs(ipv6->ip6_plen);

		from.af = AF_INET6;
		from.u.a6 = ipv6->ip6_src;
		to.af = AF_INET6;
		to.u.a6 = ipv6->ip6_dst;

                while (nexthdr == IPPROTO_ROUTING ||	/* routing header */
		       nexthdr == IPPROTO_HOPOPTS ||	/* Hop-by-Hop opts */
		       nexthdr == IPPROTO_FRAGMENT ||	/* fragmentation hdr */
		       nexthdr == IPPROTO_DSTOPTS ||	/* destination opts */
		       nexthdr == IPPROTO_AH ||		/* destination opts */
		       nexthdr == IPPROTO_ESP)		/* encap sec payload */
		{
			struct {
				uint8_t nexthdr;
				uint8_t length;
			} ext_hdr;
			uint16_t ext_hdr_len;

			/* Catch broken packets */
			if ((offset + sizeof ext_hdr) > len)
				return;

			/* Cannot handle fragments. */
			if (nexthdr == IPPROTO_FRAGMENT)
				return;

			memcpy(&ext_hdr, (u_char *)ipv6 + offset,
			       sizeof ext_hdr);
			nexthdr = ext_hdr.nexthdr;
			ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

			if (ext_hdr_len > payload_len)
				return;

			offset += ext_hdr_len;
			payload_len -= ext_hdr_len;
		}

		if ((offset + payload_len) > len || payload_len == 0)
			return;

		proto = nexthdr;
		pkt += offset;
		len -= offset;
		pf = PF_INET6;
		break;
	    }
	default:
		return;
	}

	/* Transport. */
	switch (proto) {
	case IPPROTO_UDP: {
		if (len < sizeof *udp)
			return;
		udp = (void *) pkt;
		switch (from.af) {
		case AF_INET:
		case AF_INET6:
			sport = ntohs(udp->uh_sport);
			dport = ntohs(udp->uh_dport);
			break;
		default:
			abort();
		}
		pkt += sizeof *udp;
		len -= sizeof *udp;
		break;
	    }
	default:
		return;
	}

	/* Application. */
	if (len < sizeof dns)
		return;
	memcpy(&dns, pkt, sizeof dns);

	/* Policy filtering. */
	if (!ISC_LIST_EMPTY(vlans)) {
		vlan_ptr vl;

		for (vl = ISC_LIST_HEAD(vlans);
		     vl != NULL;
		     vl = ISC_LIST_NEXT(vl, link))
			if (vl->vlan == vlan)
				break;
		if (vl == NULL)
			return;
	}
	if (dns.qr == 0 && dport == dns_port) {
		if ((msg_wanted & MSG_INITIATE) == 0)
			return;
		initiator = from;
		responder = to;
	} else if (dns.qr != 0 && sport == dns_port) {
		if ((msg_wanted & MSG_RESPONSE) == 0)
			return;
		initiator = to;
		responder = from;
	} else {
		return;
	}
	if (!((ISC_LIST_EMPTY(initiators) ||
	       ep_present(&initiators, initiator)) &&
	      (ISC_LIST_EMPTY(responders) ||
	       ep_present(&responders, responder))))
		return;
	if (!(((msg_wanted & MSG_QUERY) != 0 && dns.opcode == ns_o_query) ||
	      ((msg_wanted & MSG_UPDATE) != 0 && dns.opcode == ns_o_update)))
		return;
	if ((msg_wanted & MSG_ERROR) == 0 &&
	    (dns.tc != 0 || dns.rcode != ns_r_noerror))
		return;
	if (!ISC_LIST_EMPTY(myregexes)) {
		char output[SNAPLEN*4];
		ns_msg msg;
		ns_sect s;
		int ok;

		ok = FALSE;
		if (ns_initparse(pkt, len, &msg) < 0)
			return;
		for (s = ns_s_an; s < ns_s_max && !ok; s++) {
			int count, n;
			ns_rr rr;

			count = ns_msg_count(msg, s);
			for (n = 0; n < count && !ok; n++) {
				myregex_ptr myregex;

				if (ns_parserr(&msg, s, n, &rr) < 0 ||
				    ns_sprintrr(&msg, &rr, NULL, ".",
						output, sizeof output) < 0)
					return;
				for (myregex = ISC_LIST_HEAD(myregexes);
				     myregex != NULL && !ok;
				     myregex = ISC_LIST_NEXT(myregex, link))
					if (regexec(&myregex->reg, output,
						    0, NULL, 0) == 0)
						ok = TRUE;
			}
		}
		if (!ok)
			return;
	}

	/* Policy hiding. */
	if (end_hide != 0) {
		switch (from.af) {
		case AF_INET: {
			struct in_addr *init_addr, *resp_addr;
			uint16_t *init_port;

			if (dns.qr == 0) {
				init_addr = &ip->ip_src;
				resp_addr = &ip->ip_dst;
				init_port = &udp->uh_sport;
			} else {
				init_addr = &ip->ip_dst;
				resp_addr = &ip->ip_src;
				init_port = &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
				init_addr->s_addr = HIDE_INET;
				*init_port = htons(HIDE_UDP);
			}
			if ((end_hide & END_RESPONDER) != 0)
				resp_addr->s_addr = HIDE_INET;
			ip->ip_sum = ~in_checksum((u_char *)ip, sizeof *ip);
			udp->uh_sum = 0U;
			break;
		    }
		case AF_INET6: {
			struct in6_addr *init_addr, *resp_addr;
			uint16_t *init_port;

			if (dns.qr == 0) {
				init_addr = &ipv6->ip6_src;
				resp_addr = &ipv6->ip6_dst;
				init_port = &udp->uh_sport;
			} else {
				init_addr = &ipv6->ip6_dst;
				resp_addr = &ipv6->ip6_src;
				init_port = &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
                    		memcpy(init_addr, HIDE_INET6,
				       sizeof HIDE_INET6);
				*init_port = htons(HIDE_UDP);
			}
			if ((end_hide & END_RESPONDER) != 0)
				memcpy(resp_addr, HIDE_INET6,
				       sizeof HIDE_INET6);
			udp->uh_sum = 0U;
			break;
		    }
		default:
			abort();
		}
	}
	msgcount++;

	/* Output stage. */
	if (hdr->ts.tv_sec > dumpstart &&
	    (unsigned)(hdr->ts.tv_sec - dumpstart) >= limit_seconds)
	{
		if (dump_type == nowhere)
			goto breakloop;
		if (dumper != NULL && dumper_close())
			goto breakloop;
	}
#if HAVE_BINDLIB
	if (dig_it) {
		const struct tm *tm;
		const char *via;
		char tmp[100];
		time_t t;

		t = (time_t) hdr->ts.tv_sec;
		tm = gmtime(&t);
		strftime(tmp, sizeof tmp, "%F %T", tm);
		if (mypcap->name == NULL)
			via = "\"some interface\"";
		else
			via = mypcap->name;
		fprintf(stderr, ";@ %s.%06lu - %lu octets via %s (msg #%ld)\n",
			tmp, (u_long)hdr->ts.tv_usec, (u_long)len, via,
			(long)msgcount);
		fprintf(stderr, ";: [%s]:%u ", ia_str(from), sport);
		fprintf(stderr, "-> [%s]:%u\n",	ia_str(to), dport);
		fp_nquery(pkt, len, stderr);
		fprintf(stderr, ";--\n");
	}
#endif
	if (dump_type != nowhere) {
		if (dumper == NULL)
			if (dumper_open(hdr->ts))
				goto breakloop;
		if (mypcap->dlt == linktype) {
			pcap_dump((u_char *)dumper, hdr, pkt_copy+NS_INT32SZ);
		} else {
			struct pcap_pkthdr h;
			u_char *new, *tmp;

			new = netptr - NS_INT32SZ;
			tmp = new;
			NS_PUT32(pf, tmp);
			h = *hdr;
			if (new > dlptr)
				h.caplen = (h.len -= (new - dlptr));
			else
				h.caplen = (h.len += (dlptr - new));
			pcap_dump((u_char *)dumper, &h, new);
		}
		if (flush)
			pcap_dump_flush(dumper);
	}
	if (msgcount == limit_packets) {
		if (dump_type == nowhere)
			goto breakloop;
		if (dumper != NULL && dumper_close())
			goto breakloop;
		msgcount = 0;
	}
	return;
 breakloop:
	pcap_breakloop(mypcap->pcap);
	main_exit = TRUE;
}

static int
dumper_open(struct timeval ts) {
	const char *t = NULL;

	if (dump_type == to_stdout) {
		t = "-";
	} else {
		while (ts.tv_usec >= MILLION) {
			ts.tv_sec++;
			ts.tv_usec -= MILLION;
		}
		if (asprintf(&dumpname, "%s.%lu.%06lu",
			     dump_base, (u_long) ts.tv_sec,
			     (u_long) ts.tv_usec) < 0 ||
		    asprintf(&dumpnamepart, "%s.part", dumpname) < 0)
		{
			perror("asprintf");
			return (TRUE);
		}
		t = dumpnamepart;
	}
	dumper = pcap_dump_open(pcap_dead, t);
	if (dumper == NULL) {
		fprintf(stderr, "pcap dump open: %s\n",
			pcap_geterr(pcap_dead));
		return (TRUE);
	}
	dumpstart = ts.tv_sec;
	alarm(limit_seconds);
	return (FALSE);
}

static int
dumper_close(void) {
	int ret = FALSE;

	alarm(0);
	pcap_dump_close(dumper); dumper = FALSE;
	if (dump_type == to_stdout) {
		assert(dumpname == NULL);
		assert(dumpnamepart == NULL);
		if (verbose)
			fprintf(stderr, "%s: breaking\n", ProgramName);
		ret = TRUE;
	} else {
		char *cmd = NULL;;

		if (verbose)
			fprintf(stderr, "%s: closing %s\n",
				ProgramName, dumpname);
		rename(dumpnamepart, dumpname);
		if (kick_cmd != NULL)
			if (asprintf(&cmd, "%s %s &", kick_cmd, dumpname) < 0){
				perror("asprintf");
				cmd = NULL;
			}
		free(dumpnamepart); dumpnamepart = NULL;
		free(dumpname); dumpname = NULL;
		if (cmd != NULL) {
			setuid(getuid());
			setgid(getgid());
			system(cmd);
			free(cmd);
		}
	}
	return (ret);
}

static void
sigclose(int signum __attribute__((unused))) {
	(void) dumper_close();
}

static void
sigbreak(int signum __attribute__((unused))) {
	fprintf(stderr, "%s: signalled break\n", ProgramName);
	main_exit = TRUE;
}

static uint16_t
in_checksum(const u_char *ptr, size_t len) {
	unsigned sum = 0, top;

	/* Main body. */
	while (len >= NS_INT16SZ) {
		sum += *(const uint16_t *)ptr;
		ptr += NS_INT16SZ;
		len -= NS_INT16SZ;
	}

	/* Leftover octet? */
	if (len != 0)
		sum += *ptr;

	/* Leftover carries? */
	while ((top = (sum >> 16)) != 0)
		sum = ((uint16_t)sum) + top;

	/* Caller should ~ this result. */
	return ((uint16_t) sum);
}
