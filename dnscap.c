/* dnscap - DNS capture utility
 *
 * Paul Vixie (original) and Duane Wessels (IPv6 port)
 */

#ifndef lint
static const char rcsid[] = "$Id: dnscap.c,v 1.1.1.1 2007-05-02 18:32:07 vixie Exp $";
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
#endif

#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <assert.h>
#include <netdb.h>
#include <pcap.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct pcapif {
	ISC_LINK(struct pcapif)	link;
	const char *		name;
	int			fdes;
	pcap_t *		pcap;
	int			dlt;
};
typedef struct pcapif *pcapif_ptr;
typedef ISC_LIST(struct pcapif) pcapif_list;

struct vlan {
	ISC_LINK(struct vlan)	link;
	u_int			vlan;
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

/* Forward. */

static void setsig(int, int);
static void usage(const char *) __attribute__((noreturn));
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
static u_int16_t in_checksum(const u_char *, size_t);

/* Private data. */

static const char *ProgramName = "amnesia";
static int verbose = FALSE;
static int flush = FALSE;
static vlan_list vlans;
static u_int msg_wanted = MSG_QUERY|MSG_INITIATE|MSG_RESPONSE;
static u_int end_hide = 0U;
static endpoint_list initiators;
static endpoint_list responders;
static pcapif_list pcapifs;
static const char *dump_base = NULL;
static const char *kick_cmd = NULL;
static u_int limit_seconds = DAY;
static u_int limit_packets = BILLION;
static fd_set pcapif_fdset;
static int pcap_maxfd;
static int linktype;
static pcap_t *dead;
static pcap_dumper_t *dumper;
static time_t dumpstart;
static u_int dumpcount;
static char *dumpname, *dumpnamepart;
static char *bpft;
static u_int dns_port = DNS_PORT;
static int promisc = FALSE;
static char errbuf[PCAP_ERRBUF_SIZE];
static int v6bug = FALSE;
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
	fprintf(stderr, "%s: usage error (%s)\n", ProgramName, msg);
	fprintf(stderr, "\n");
	fprintf(stderr,
		"usage: %s [-avf6] [-i <if>]+ [-l <vlan>]+ [-p <port>]\n"
		"\t[-m [quire]] [-h [ir]] [-q <host>]+ [-r <host>]+\n"
		"\t[-d <base> [-k <cmd>]] [-t <lim>] [-c <lim>]\n",
		ProgramName);
	fprintf(stderr, "\noptions:\n"
			"\t-a         collect packets promiscuously\n"
			"\t-v         be verbose to stderr\n"
			"\t-f         flush output on every packet\n"
			"\t-6         compensate for PCAP/BPF IPv6 bug\n"
			"\t-i <if>    pcap interface(s)\n"
			"\t-l <vlan>  pcap vlan(s)\n"
			"\t-p <port>  dns port (default: 53)\n"
			"\t-m [quire] query, update, initiate, response, err\n"
			"\t-h [ir]    hide initiators and/or responders\n"
			"\t-q <host>  initiator(s)\n"
			"\t-r <host>  responder(s)\n"
			"\t-d <base>  dump to <base>.<timesec>.<timeusec>\n"
			"\t-k <cmd>   kick off <cmd> when each dump closes\n"
			"\t-t <lim>   close dump or exit every <lim> secs\n"
			"\t-c <lim>   close dump or exit every <lim> pkts\n");
	exit(1);
}

static void
parse_args(int argc, char *argv[]) {
	pcapif_ptr pcapif;
	vlan_ptr vlan;
	char *p, ch;
	int i;

	if ((p = strrchr(argv[0], '/')) == NULL)
		ProgramName = argv[0];
	else
		ProgramName = p+1;
	ISC_LIST_INIT(vlans);
	ISC_LIST_INIT(pcapifs);
	ISC_LIST_INIT(initiators);
	ISC_LIST_INIT(responders);
	while ((ch = getopt(argc, argv, "avf6i:l:p:m:h:q:r:d:k:t:c:")) != EOF){
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
		case '6':
			v6bug = TRUE;
			break;
		case 'i':
			pcapif = malloc(sizeof *pcapif);
			ISC_LINK_INIT(pcapif, link);
			pcapif->name = strdup(optarg);
			assert(pcapif->name != NULL);
			pcapif->fdes = -1;
			ISC_LIST_APPEND(pcapifs, pcapif, link);
			break;
		case 'l':
			i = atoi(optarg);
			if (i < 1 || i > MAX_VLAN)
				usage("vlan must be an integer 1..4095");
			vlan = malloc(sizeof *vlan);
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
			break;
		case 'k':
			if (dump_base == NULL)
				usage("-k depends on -d");
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
		default:
			usage("unrecognized command line option");
		}
	}
	assert(msg_wanted != 0U);
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
	if (ISC_LIST_EMPTY(pcapifs)) {
		const char *name;
#ifdef __linux__
		name = NULL;	/* "all interfaces" */
#else
		name = pcap_lookupdev(errbuf);
		if (name == NULL) {
			fprintf(stderr, "%s: pcap: %s\n", ProgramName, errbuf);
			exit(1);
		}
#endif
		pcapif = malloc(sizeof *pcapif);
		ISC_LINK_INIT(pcapif, link);
		pcapif->name = name;
		pcapif->fdes = -1;
		ISC_LIST_APPEND(pcapifs, pcapif, link);
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
	endpoint_ptr ep = malloc(sizeof *ep);

	assert(ep != NULL);
	ISC_LINK_INIT(ep, link);
	ep->ia = ia;
	ISC_LIST_APPEND(*list, ep, link);
}

static void
prepare_bpft(void) {
	u_int udp10_mbs, udp10_mbc, udp11_mbs, udp11_mbc;
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
	pcapif_ptr pcapif;

	assert(!ISC_LIST_EMPTY(pcapifs));
	linktype = -1;
	FD_ZERO(&pcapif_fdset);
	pcap_maxfd = 0;
	for (pcapif = ISC_LIST_HEAD(pcapifs);
	     pcapif != NULL;
	     pcapif = ISC_LIST_NEXT(pcapif, link))
	{
		struct bpf_program bpfp;

		errbuf[0] = '\0';
		pcapif->pcap = pcap_open_live(pcapif->name, SNAPLEN, promisc,
					      TO_MS, errbuf);
		if (pcapif->pcap == NULL) {
			fprintf(stderr, "%s: pcap_open_live: %s\n",
				ProgramName, errbuf);
			exit(1);
		}
		if (errbuf[0] != '\0')
			fprintf(stderr, "%s: pcap warning: %s",
				ProgramName, errbuf);
		pcapif->dlt = pcap_datalink(pcapif->pcap);
		if (linktype == -1)
			linktype = pcapif->dlt;
		else if (linktype != pcapif->dlt)
			linktype = DLT_LOOP;
		pcapif->fdes = pcap_get_selectable_fd(pcapif->pcap);
		FD_SET(pcapif->fdes, &pcapif_fdset);
		if (pcapif->fdes > pcap_maxfd)
			pcap_maxfd = pcapif->fdes;
		if (pcap_setnonblock(pcapif->pcap, TRUE, errbuf) < 0) {
			fprintf(stderr, "%s: pcap_setnonblock: %s\n",
				ProgramName, errbuf);
			exit(1);
		}
		if (pcap_compile(pcapif->pcap, &bpfp, bpft, TRUE, 0) < 0 ||
		    pcap_setfilter(pcapif->pcap, &bpfp) < 0) {
			fprintf(stderr, "%s: pcap error: %s\n",
				ProgramName, pcap_geterr(pcapif->pcap));
			exit(1);
		}
		pcap_freecode(&bpfp);
	}
	assert(linktype != -1);
	dead = pcap_open_dead(linktype, SNAPLEN);
	if (dead == NULL) {
		fprintf(stderr, "%s: pcap_open_dead failed\n", ProgramName);
		exit(1);
	}
}

static void
poll_pcaps(void) {
	pcapif_ptr pcapif;
	fd_set readfds;
	int n;

	readfds = pcapif_fdset;
	n = select(pcap_maxfd+1, &readfds, NULL, NULL, NULL);
	if (n < 0) {
		perror("select");
		main_exit = TRUE;
		return;
	}
	/* Poll them all. */
	for (pcapif = ISC_LIST_HEAD(pcapifs);
	     pcapif != NULL;
	     pcapif = ISC_LIST_NEXT(pcapif, link))
	{
		n = pcap_dispatch(pcapif->pcap, -1, live_packet,
				  (u_char *)pcapif);
		if (n == -1)
			fprintf(stderr, "%s: pcap_dispatch: %s\n",
				ProgramName, errbuf);
		if (n < 0) {
			main_exit = TRUE;
			return;
		}
	}
}

static void
close_pcaps(void) {
	pcapif_ptr pcapif;

	for (pcapif = ISC_LIST_HEAD(pcapifs);
	     pcapif != NULL;
	     pcapif = ISC_LIST_NEXT(pcapif, link))
		pcap_close(pcapif->pcap);
	pcap_close(dead);
}

static void
live_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *opkt) {
	u_char pkt_copy[SNAPLEN+NS_INT32SZ],
		*pkt = pkt_copy+NS_INT32SZ,
		*netpkt;
	iaddr from, to, initiator, responder;
	pcapif_ptr pcapif = (pcapif_ptr) user;
	u_int etype, proto, sport, dport;
	size_t len = hdr->caplen;
	struct udphdr *udp;
	const HEADER *dns;
	struct ip *ip;
	struct ip6_hdr *ipv6;
	u_int vlan, pf;

	memcpy(pkt, opkt, len);

	/* Data link. */
	vlan = 0;
	switch (pcapif->dlt) {
	case DLT_NULL: {
		u_int32_t x;

		if (len < NS_INT32SZ)
			return;
		x = *(const u_int32_t *)pkt;
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
		u_int32_t x;

		if (len < NS_INT32SZ)
			return;
		x = ns_get32(pkt);
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
			vlan = ntohs(*(const u_int16_t *) pkt);
			pkt += 2;
			len -= 2;
			if (vlan < 1 || vlan > MAX_VLAN)
				return;
			etype = ntohs(*(const u_int16_t *) pkt);
			pkt += 2;
			len -= 2;
		}
		break;
	    }
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL: {
		if (len < 16)
			return;
		etype = ntohs(*(const u_int16_t *) &pkt[14]);
		pkt += 16;
		len -= 16;
		break;
	    }
#endif
	default:
		return;
	}

	/* Network. */
	netpkt = pkt;
	ip = NULL;
	ipv6 = NULL;
	switch (etype) {
	case ETHERTYPE_IP: {
		u_int offset;

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
		u_int16_t payload_len;
		u_int8_t nexthdr;
		u_int offset;

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
				u_int8_t nexthdr;
				u_int8_t length;
			} ext_hdr;
			u_int16_t ext_hdr_len;

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
	if (len < sizeof *dns)
		return;
	dns = (void *) pkt;

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
	if (dns->qr == 0 && dport == dns_port) {
		if ((msg_wanted & MSG_INITIATE) == 0)
			return;
		initiator = from;
		responder = to;
	} else if (dns->qr != 0 && sport == dns_port) {
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
	if (!(((msg_wanted & MSG_QUERY) != 0 && dns->opcode == ns_o_query) ||
	      ((msg_wanted & MSG_UPDATE) != 0 && dns->opcode == ns_o_update)))
		return;
	if ((msg_wanted & MSG_ERROR) == 0 &&
	    (dns->tc != 0 || dns->rcode != ns_r_noerror))
		return;

	/* Policy hiding. */
	if (end_hide != 0) {
		switch (from.af) {
		case AF_INET: {
			struct in_addr *init_addr, *resp_addr;
			u_int16_t *init_port;

			if (dns->qr == 0) {
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
			u_int16_t *init_port;

			if (dns->qr == 0) {
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

	if (dumper != NULL && hdr->ts.tv_sec > dumpstart &&
	    (u_int)(hdr->ts.tv_sec - dumpstart) >= limit_seconds)
		if (dumper_close()) {
			main_exit = TRUE;
			return;
		}
	if (dumper == NULL)
		if (dumper_open(hdr->ts)) {
			main_exit = TRUE;
			return;
		}
	if (pcapif->dlt == linktype) {
		pcap_dump((u_char *)dumper, hdr, pkt_copy+NS_INT32SZ);
	} else {
		struct pcap_pkthdr h;

		netpkt -= NS_INT32SZ;
		ns_put32(pf, netpkt);
		h = *hdr;
		h.caplen -= (netpkt - pkt);
		h.len -= (netpkt - pkt);
		pcap_dump((u_char *)dumper, &h, netpkt);
	}
	if (flush)
		pcap_dump_flush(dumper);
	if (++dumpcount == limit_packets) {
		dumpcount = 0;
		if (dumper_close())
			return;
	}
}

static int
dumper_open(struct timeval ts) {
	const char *t = NULL;

	if (dump_base == NULL) {
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
	dumper = pcap_dump_open(dead, t);
	if (dumper == NULL) {
		fprintf(stderr, "pcap: %s\n", pcap_geterr(dead));
		return (TRUE);
	}
	dumpstart = ts.tv_sec;
	alarm(limit_seconds);
	return (FALSE);
}

static int
dumper_close(void) {
	FILE *dumpfile = pcap_dump_file(dumper);
	int ret = FALSE;

	alarm(0);
	pcap_dump_close(dumper); dumper = FALSE;
	if (dumpfile == stdout) {
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

static u_int16_t
in_checksum(const u_char *ptr, size_t len) {
	unsigned sum = 0, top;

	/* Main body. */
	while (len >= NS_INT16SZ) {
		sum += *(const u_int16_t *)ptr;
		ptr += NS_INT16SZ;
		len -= NS_INT16SZ;
	}

	/* Leftover octet? */
	if (len != 0)
		sum += *ptr;

	/* Leftover carries? */
	while ((top = (sum >> 16)) != 0)
		sum = ((u_int16_t)sum) + top;

	/* Caller should ~ this result. */
	return ((u_int16_t) sum);
}
