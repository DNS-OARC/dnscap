/* dnscap - DNS capture utility
 *
 * By Paul Vixie (ISC) and Duane Wessels (Measurement Factory), 2007.
 */

#ifndef lint
static const char rcsid[] = "$Id$";
static const char copyright[] =
	"Copyright (c) 2007 by Internet Systems Consortium, Inc. (\"ISC\")";
static const char version_fmt[] = "V1.0-OARC-r%d (%s)";
#endif

/*
 * Copyright (c) 2007 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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
# define MY_BPFTIMEVAL bpf_timeval
#endif

#ifdef __APPLE__
# include <sys/ioctl.h>
# include <net/ethernet.h>
# include <net/bpf.h>
# include <arpa/nameser_compat.h>
#endif

#ifdef __hpux
# include <net/if.h>
# include <netinet/if_ether.h>
# define ETHER_HDR_LEN ETHER_HLEN
# define __BIT_TYPES_DEFINED
# define __HPLX
#endif

#ifdef __SVR4
# include <stdarg.h>
# include <net/if.h>
# include <net/if_arp.h>
# include <netinet/if_ether.h>
# include "snprintf.h"
# define   IP_OFFMASK      0x1fff
# define u_int32_t uint32_t
# ifndef ETHER_HDR_LEN
#  define ETHER_HDR_LEN 14
# endif
#endif

#ifndef MY_BPFTIMEVAL
# define MY_BPFTIMEVAL timeval
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
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

#ifdef __linux__
extern char *strptime(const char *, const char *, struct tm *);
#endif

#define MY_GET32(l, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
} while (0)

#define ISC_CHECK_NONE 1

#include "isc/list.h"
#include "isc/assertions.h"
#include "dump_dns.h"

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
#define	MSG_NOTIFY	0x0004

#define DIR_INITIATE	0x0001
#define DIR_RESPONSE	0x0002

#define ERR_TRUNC	0x0001
#define ERR_RCODE_BASE	0x0002
#define ERR_NO		(ERR_RCODE_BASE << ns_r_noerror)
#define ERR_FORMERR	(ERR_RCODE_BASE << ns_r_formerr)
#define ERR_SERVFAIL	(ERR_RCODE_BASE << ns_r_servfail)
#define ERR_NXDOMAIN	(ERR_RCODE_BASE << ns_r_nxdomain)
#define ERR_NOTIMPL	(ERR_RCODE_BASE << ns_r_notimpl)
#define ERR_REFUSED	(ERR_RCODE_BASE << ns_r_refused)
#define ERR_YES		(0xffffffff & ~ERR_NO)

#define END_INITIATOR	0x0001
#define END_RESPONDER	0x0002

#define HIDE_INET	0x7f7f7f7f
#define HIDE_INET6	"\177\177\177\177\177\177\177\177" \
			"\177\177\177\177\177\177\177\177"
#define HIDE_PORT	54321

#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN	0x8100
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#define THOUSAND	1000
#define MILLION		(THOUSAND*THOUSAND)
#define MAX_VLAN	4095
#define DNS_PORT	53
#define TO_MS		1
#define SNAPLEN		65536
#define TRUE		1
#define FALSE		0
#define REGEX_CFLAGS	(REG_EXTENDED|REG_ICASE|REG_NOSUB|REG_NEWLINE)
#define MAX_TCP_WINDOW	(0xFFFF << 14)

/* Data structures. */

typedef struct MY_BPFTIMEVAL my_bpftimeval;

typedef struct {
	int			af;
	union {
		struct in_addr		a4;
		struct in6_addr		a6;
	} u;
} iaddr;

struct endpoint {
	LINK(struct endpoint)  link;
	iaddr			ia;
};
typedef struct endpoint *endpoint_ptr;
typedef LIST(struct endpoint) endpoint_list;

struct mypcap {
	LINK(struct mypcap)	link;
	const char *		name;
	int			fdes;
	pcap_t *		pcap;
	int			dlt;
	struct pcap_stat	ps0, ps1;
};
typedef struct mypcap *mypcap_ptr;
typedef LIST(struct mypcap) mypcap_list;

struct vlan {
	LINK(struct vlan)	link;
	unsigned		vlan;
};
typedef struct vlan *vlan_ptr;
typedef LIST(struct vlan) vlan_list;

struct text {
	LINK(struct text)	link;
	size_t			len;
	char *			text;
};
typedef struct text *text_ptr;
typedef LIST(struct text) text_list;
#define text_size(len) (sizeof(struct text) + len)

struct myregex {
	LINK(struct myregex)  link;
	regex_t			reg;
	char *			str;
	int			not;
};
typedef struct myregex *myregex_ptr;
typedef LIST(struct myregex) myregex_list;

struct tcpstate {
	LINK(struct tcpstate)  link;
	iaddr			saddr;
	iaddr			daddr;
	uint16_t		sport;
	uint16_t		dport;
	uint32_t		start;		/* seq# of tcp payload start */
	uint32_t		maxdiff;	/* maximum (seq# - start) */
	uint16_t		dnslen;
	time_t			last_use;
};
typedef struct tcpstate *tcpstate_ptr;
typedef LIST(struct tcpstate) tcpstate_list;

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
static void text_free(text_list *);
static void open_pcaps(void);
static void poll_pcaps(void);
static void breakloop_pcaps(void);
static void close_pcaps(void);
static void dl_pkt(u_char *, const struct pcap_pkthdr *, const u_char *);
static void network_pkt(const char *, my_bpftimeval, unsigned,
			const u_char *, size_t);
static void output(const char *descr, iaddr from, iaddr to, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *dnspkt, unsigned dnslen);
static int dumper_open(my_bpftimeval);
static int dumper_close(void);
static void sigclose(int);
static void sigbreak(int);
static uint16_t in_checksum(const u_char *, size_t);

/* Private data. */

static const char *ProgramName = "amnesia";
static int dumptrace = 0;
static int flush = FALSE;
static vlan_list vlans;
static unsigned msg_wanted = MSG_QUERY;
static unsigned dir_wanted = DIR_INITIATE|DIR_RESPONSE;
static unsigned end_hide = 0U;
static unsigned err_wanted = ERR_NO | ERR_YES; /* accept all by default */
static tcpstate_list tcpstates;
static int tcpstate_count = 0;
static endpoint_list initiators, not_initiators;
static endpoint_list responders, not_responders;
static myregex_list myregexes;
static mypcap_list mypcaps;
static mypcap_ptr pcap_offline = NULL;
static const char *dump_base = NULL;
static enum {nowhere, to_stdout, to_file} dump_type = nowhere;
static const char *kick_cmd = NULL;
static unsigned limit_seconds = 0U;
static time_t next_interval = 0;
static unsigned limit_packets = 0U;
static fd_set mypcap_fdset;
static int pcap_maxfd;
static pcap_t *pcap_dead;
static pcap_dumper_t *dumper;
static time_t dumpstart;
static unsigned msgcount;
static char *dumpname, *dumpnamepart;
static char *bpft;
static unsigned dns_port = DNS_PORT;
static int promisc = TRUE;
static char errbuf[PCAP_ERRBUF_SIZE];
static int v6bug = FALSE;
static int wantfrags = FALSE;
static int wanttcp = FALSE;
static int preso = FALSE;
static int main_exit = FALSE;
static int alarm_set = FALSE;
static time_t start_time = 0;
static time_t stop_time = 0;
static int print_pcap_stats = FALSE;

/* Public. */

int
main(int argc, char *argv[]) {
	res_init();
	parse_args(argc, argv);
	if (start_time) {
		time_t now;
		time(&now);
		if (now < start_time) {
			char when[100];
			struct tm *tm = gmtime(&start_time);
			strftime(when, sizeof when, "%F %T", tm);
			fprintf(stderr, "Sleeping for %d seconds until %s UTC\n",
				(int) (start_time - now), when);
			sleep(start_time - now);
			fprintf(stderr, "Awake.\n");
		}
	}
	prepare_bpft();
	open_pcaps();
	INIT_LIST(tcpstates);
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

static const char *
version(void)
{
	int revnum;
	char scandate[32];
	static char vbuf[128];
	const char *sep = " \t";
	char *copy = strdup(rcsid);
	char *t;
	if (NULL == (t = strtok(copy, sep)))
		return version_fmt;
	if (NULL == (t = strtok(NULL, sep)))
		return version_fmt;
	if (NULL == (t = strtok(NULL, sep)))
		return version_fmt;
	revnum = atoi(t);
	if (NULL == (t = strtok(NULL, sep)))
		return version_fmt;
	strncpy(scandate, t, 32);
	snprintf(vbuf, 128, version_fmt, revnum, scandate);
	free(copy);
	return vbuf;
	
}

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

static time_t
xtimegm(struct tm *tmp)
{
#if defined (__SVR4) && defined (__sun)
	putenv("TZ=");
	return mktime(tmp);
#else
	return timegm(tmp);
#endif
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
	fprintf(stderr, "%s: version %s\n\n", ProgramName, version());
	fprintf(stderr,
		"usage: %s\n"
		"\t[-?pd1g6fT] [-i <if>]+ [-r <file>]+ [-l <vlan>]+\n"
		"\t[-u <port>] [-m [qun]] [-e [nytfsxir]]\n"
		"\t[-h [ir]] [-s [ir]]\n"
		"\t[-a <host>]+ [-z <host>]+ [-A <host>]+ [-Z <host>]+\n"
		"\t[-w <base> [-k <cmd>]] [-t <lim>] [-c <lim>]\n"
		"\t[-x <pat>]+ [-X <pat>]+\n"
		"\t[-B <datetime>]+ [-E <datetime>]+\n",
		ProgramName);
}

static void
help_2(void) {
	help_1();
	fprintf(stderr,
		"\noptions:\n"
		"\t-? or -\\?  print these instructions and exit\n"
		"\t-p         do not put interface in promiscuous mode\n"
		"\t-d         dump verbose trace information to stderr\n"
		"\t-1         flush output on every packet\n"
		"\t-g         dump packets dig-style on stderr\n"
		"\t-6         compensate for PCAP/BPF IPv6 bug\n"
		"\t-f         include fragmented packets\n"
		"\t-T         include TCP packets (DNS header filters will inspect only the\n"
		"\t           first DNS header, and the result will apply to all messages\n"
		"\t           in the TCP stream; DNS payload filters will not be applied.)\n"
		"\t-i <if>    select this live interface(s)\n"
		"\t-r <file>  read this pcap file\n"
		"\t-l <vlan>  select only these vlan(s)\n"
		"\t-u <port>  dns port (default: 53)\n"
		"\t-m [qun]   select messages: query, update, notify\n"
		"\t-s [ir]    select sides: initiations, responses\n"
		"\t-h [ir]    hide initiators and/or responders\n"
		"\t-e [nytfsxir] select error/response code\n"
		"\t               n = no error\n"
		"\t               y = any error\n"
		"\t               t = truncated response\n"
		"\t               f = format error (rcode 1)\n"
		"\t               s = server failure (rcode 2)\n"
		"\t               x = nxdomain (rcode 3)\n"
		"\t               i = not implemented (rcode 4)\n"
		"\t               r = refused (rcode 5)\n"
		"\t-a <host>  want messages from these initiator(s)\n"
		"\t-z <host>  want messages from these responder(s)\n"
		"\t-A <host>  want messages not from these initiator(s)\n"
		"\t-Z <host>  want messages not from these responder(s)\n"
		"\t-w <base>  dump to <base>.<timesec>.<timeusec>\n"
		"\t-k <cmd>   kick off <cmd> when each dump closes\n"
		"\t-t <lim>   close dump or exit every/after <lim> secs\n"
		"\t-c <lim>   close dump or exit every/after <lim> pkts\n"
		"\t-x <pat>   select messages matching regex <pat>\n"
		"\t-X <pat>   select messages not matching regex <pat>\n"
                "\t-B <datetime> begin collecting at this date and time\n"
                "\t-E <datetime> end collecting at this date and time\n"
		);
}

static void
parse_args(int argc, char *argv[]) {
#if HAVE_BINDLIB
	myregex_ptr myregex;
#endif
	mypcap_ptr mypcap;
	unsigned long ul;
	vlan_ptr vlan;
	unsigned u;
	int i, ch;
	char *p;

	if ((p = strrchr(argv[0], '/')) == NULL)
		ProgramName = argv[0];
	else
		ProgramName = p+1;
	INIT_LIST(vlans);
	INIT_LIST(mypcaps);
	INIT_LIST(initiators);
	INIT_LIST(responders);
	INIT_LIST(not_initiators);
	INIT_LIST(not_responders);
	INIT_LIST(myregexes);
	while ((ch = getopt(argc, argv,
			"pd1g6f?i:r:l:u:Tm:s:h:e:a:z:A:Z:w:k:t:c:x:X:B:E:S")
		) != EOF)
	{
		switch (ch) {
		case 'p':
			promisc = FALSE;
			break;
		case 'd':
			dumptrace++;
			break;
		case '1':
			flush = TRUE;
			break;
		case 'g':
			preso = TRUE;
			break;
		case '6':
			v6bug = TRUE;
			break;
		case 'f':
			wantfrags = TRUE;
			break;
		case '?':
			help_2();
			exit(0);
			break;
		case 'i':
			if (pcap_offline != NULL)
				usage("-i makes no sense after -r");
			mypcap = malloc(sizeof *mypcap);
			assert(mypcap != NULL);
			INIT_LINK(mypcap, link);
			mypcap->name = strdup(optarg);
			assert(mypcap->name != NULL);
			mypcap->fdes = -1;
			memset(&mypcap->ps0, 0, sizeof(mypcap->ps0));
			memset(&mypcap->ps1, 0, sizeof(mypcap->ps1));
			APPEND(mypcaps, mypcap, link);
			break;
		case 'r':
			if (!EMPTY(mypcaps))
				usage("-r makes no sense after -i");
			pcap_offline = malloc(sizeof *pcap_offline);
			assert(pcap_offline != NULL);
			INIT_LINK(pcap_offline, link);
			pcap_offline->name = strdup(optarg);
			assert(pcap_offline->name != NULL);
			pcap_offline->fdes = -1;
			APPEND(mypcaps, pcap_offline, link);
			break;
		case 'l':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0' || ul > MAX_VLAN)
				usage("vlan must be 0 or an integer 1..4095");
			vlan = malloc(sizeof *vlan);
			assert(vlan != NULL);
			INIT_LINK(vlan, link);
			vlan->vlan = (unsigned) ul;
			APPEND(vlans, vlan, link);
			break;
		case 'T':
			wanttcp = TRUE;
			break;
		case 'u':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0' || ul < 1U || ul > 65535U)
				usage("port must be an integer 1..65535");
			dns_port = (unsigned) ul;
			break;
		case 'm':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'q': u |= MSG_QUERY; break;
				case 'u': u |= MSG_UPDATE; break;
				case 'n': u |= MSG_NOTIFY; break;
				default: usage("-m takes only [qun]");
				}
			msg_wanted = u;
			break;
		case 's':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'i': u |= DIR_INITIATE; break;
				case 'r': u |= DIR_RESPONSE; break;
				default: usage("-s takes only [ir]");
				}
			dir_wanted = u;
			break;
		case 'h':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'i': u |= END_INITIATOR; break;
				case 'r': u |= END_RESPONDER; break;
				default: usage("-h takes only [ir]");
				}
			end_hide = u;
			break;
		case 'e':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'n': u |= ERR_NO; break;
				case 'y': u |= ERR_YES; break;
				case 't': u |= ERR_TRUNC; break;
				case 'f': u |= ERR_FORMERR; break;
				case 's': u |= ERR_SERVFAIL; break;
				case 'x': u |= ERR_NXDOMAIN; break;
				case 'i': u |= ERR_NOTIMPL; break;
				case 'r': u |= ERR_REFUSED; break;
				default: usage("-e takes only [nytfsxir]");
				}
			err_wanted = u;
			break;
		case 'a':
			endpoint_arg(&initiators, optarg);
			break;
		case 'z':
			endpoint_arg(&responders, optarg);
			break;
		case 'A':
			endpoint_arg(&not_initiators, optarg);
			break;
		case 'Z':
			endpoint_arg(&not_responders, optarg);
			break;
		case 'w':
			dump_base = optarg;
			if (strcmp(optarg, "-") == 0)
				dump_type = to_stdout;
			else
				dump_type = to_file;
			break;
		case 'k':
			if (dump_type != to_file)
				usage("-k depends on -w"
				      " (note: can't be stdout)");
			kick_cmd = optarg;
			break;
		case 't':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0')
				usage("argument to -t must be an integer");
			limit_seconds = (unsigned) ul;
			break;
		case 'c':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0')
				usage("argument to -c must be an integer");
			limit_packets = (unsigned) ul;
			break;
		case 'x':
			/* FALLTHROUGH */
		case 'X':
#if HAVE_BINDLIB
			myregex = malloc(sizeof *myregex);
			assert(myregex != NULL);
			INIT_LINK(myregex, link);
			myregex->str = strdup(optarg);
			i = regcomp(&myregex->reg, myregex->str, REGEX_CFLAGS);
			if (i != 0) {
				regerror(i, &myregex->reg,
					 errbuf, sizeof errbuf);
				usage(errbuf);
			}
			myregex->not = (ch == 'X');
			APPEND(myregexes, myregex, link);
			break;
#else
			usage("-x option is disabled due to lack of libbind");
#endif
		case 'B':
			{
				struct tm tm;
				memset(&tm, '\0', sizeof(tm));
				if (NULL == strptime(optarg, "%F %T", &tm))
					usage("--B arg must have format YYYY-MM-DD HH:MM:SS");
				start_time = xtimegm(&tm);
			}
			break;
		case 'E':
			{
				struct tm tm;
				memset(&tm, '\0', sizeof(tm));
				if (NULL == strptime(optarg, "%F %T", &tm))
					usage("--E arg must have format YYYY-MM-DD HH:MM:SS");
				stop_time = xtimegm(&tm);
			}
			break;
		case 'S':
			print_pcap_stats = TRUE;
		default:
			usage("unrecognized command line option");
		}
	}
	assert(msg_wanted != 0U);
	assert(err_wanted != 0U);
	if (dump_type == nowhere && !preso)
		usage("without -w or -g, there would be no output");
	if (end_hide != 0U && wantfrags)
		usage("the -h and -f options are incompatible");
	if (dumptrace >= 1) {
		endpoint_ptr ep;
		const char *sep;
		myregex_ptr mr;

		fprintf(stderr, "%s: version %s\n", ProgramName, version());
		fprintf(stderr,
		"%s: msg %c%c%c, side %c%c, hide %c%c, err %c%c%c%c%c%c%c%c, t %u, c %u\n",
			ProgramName,
			(msg_wanted & MSG_QUERY) != 0 ? 'Q' : '.',
			(msg_wanted & MSG_UPDATE) != 0 ? 'U' : '.',
			(msg_wanted & MSG_NOTIFY) != 0 ? 'N' : '.',
			(dir_wanted & DIR_INITIATE) != 0 ? 'I' : '.',
			(dir_wanted & DIR_RESPONSE) != 0 ? 'R' : '.',
			(end_hide & END_INITIATOR) != 0 ? 'I' : '.',
			(end_hide & END_RESPONDER) != 0 ? 'R' : '.',
			(err_wanted & ERR_NO) != 0 ? 'N' : '.',
			(err_wanted & ERR_YES) == ERR_YES ? 'Y' : '.',
			(err_wanted & ERR_TRUNC) != 0 ? 't' : '.',
			(err_wanted & ERR_FORMERR) != 0 ? 'f' : '.',
			(err_wanted & ERR_SERVFAIL) != 0 ? 's' : '.',
			(err_wanted & ERR_NXDOMAIN) != 0 ? 'x' : '.',
			(err_wanted & ERR_NOTIMPL) != 0 ? 'i' : '.',
			(err_wanted & ERR_REFUSED) != 0 ? 'r' : '.',
			limit_seconds, limit_packets);
		sep = "\tinit";
		for (ep = HEAD(initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(initiators))
			fprintf(stderr, "\n");
		sep = "\tresp";
		for (ep = HEAD(responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(responders))
			fprintf(stderr, "\n");
		sep = "\t!init";
		for (ep = HEAD(not_initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(not_initiators))
			fprintf(stderr, "\n");
		sep = "\t!resp";
		for (ep = HEAD(not_responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(not_responders))
			fprintf(stderr, "\n");
		if (!EMPTY(myregexes)) {
			fprintf(stderr, "%s: pat:", ProgramName);
			for (mr = HEAD(myregexes);
			     mr != NULL;
			     mr = NEXT(mr, link))
				fprintf(stderr, " %s/%s/",
					mr->not ? "!" : "", mr->str);
			fprintf(stderr, "\n");
		}
	}
	if (EMPTY(mypcaps)) {
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
		INIT_LINK(mypcap, link);
		mypcap->name = (name == NULL) ? NULL : strdup(name);
		mypcap->fdes = -1;
		APPEND(mypcaps, mypcap, link);
	}
	if (start_time && stop_time && start_time >= stop_time)
		usage("start time must be before stop time");
	if ((start_time || stop_time) && NULL == dump_base)
		usage("--B and --E require -w");
}

static void
endpoint_arg(endpoint_list *list, const char *arg) {
	struct addrinfo *ai;
	iaddr ia;
	void *p;

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
				p = &((struct sockaddr_in *)a->ai_addr)
					->sin_addr;
				memcpy(&ia.u.a4, p, sizeof ia.u.a4);
				break;
			case PF_INET6:
				ia.af = AF_INET6;
				p = &((struct sockaddr_in6 *)a->ai_addr)
					->sin6_addr;
				memcpy(&ia.u.a6, p, sizeof ia.u.a6);
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
	INIT_LINK(ep, link);
	ep->ia = ia;
	APPEND(*list, ep, link);
}

static void
prepare_bpft(void) {
	unsigned udp10_mbs, udp10_mbc, udp11_mbs, udp11_mbc;
	text_list bpfl;
	text_ptr text;
	size_t len;

	/* Prepare the must-be-set and must-be-clear tests. */
	udp10_mbs = udp10_mbc = udp11_mbs = udp11_mbc = 0U;
	if ((dir_wanted & DIR_INITIATE) != 0) {
		if ((dir_wanted & DIR_RESPONSE) == 0)
			udp10_mbc |= UDP10_QR_MASK;
	} else if ((dir_wanted & DIR_RESPONSE) != 0) {
		udp10_mbs |= UDP10_QR_MASK;
	}
	if ((msg_wanted & MSG_UPDATE) != 0) {
		if ((msg_wanted & (MSG_QUERY|MSG_NOTIFY)) == 0)
			udp10_mbs |= (ns_o_update << UDP10_OP_SHIFT);
	} else if ((msg_wanted & MSG_NOTIFY) != 0) {
		if ((msg_wanted & (MSG_QUERY|MSG_UPDATE)) == 0)
			udp10_mbs |= (ns_o_notify << UDP10_OP_SHIFT);
	} else if ((msg_wanted & MSG_QUERY) != 0) {
		udp10_mbc |= UDP10_OP_MASK;
	}
	if (err_wanted == ERR_NO) {
		udp10_mbc |= UDP10_TC_MASK;
		udp11_mbc |= UDP11_RC_MASK;
	}

	/* Make a BPF program to do early course kernel-level filtering. */
	INIT_LIST(bpfl);
	len = 0;
	if (!EMPTY(vlans))
		len += text_add(&bpfl, "vlan and ( ");
	if (wantfrags) {
		len += text_add(&bpfl, "ip[6:2] & 0x1fff != 0 or ( ");
		/* XXX what about IPv6 fragments? */
	}
	if (wanttcp) {
		len += text_add(&bpfl, "( tcp port %d or ( ", dns_port);
		/* tcp packets can be filtered by initiators/responders, but
		 * not mbs/mbc. */
	}
	len += text_add(&bpfl, "udp port %d", dns_port);
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

		if (err_wanted != ERR_NO) {
			len += text_add(&bpfl, " and (");
			if ((err_wanted & ERR_TRUNC) != 0) {
				len += text_add(&bpfl,
						"udp[10] & 0x%x = 0x%x or ",
						UDP10_TC_MASK, UDP10_TC_MASK);
			}
			len += text_add(&bpfl,
					"0x%x << (udp[11] & 0xf) & 0x%x != 0)",
					ERR_RCODE_BASE, err_wanted);
		}
	}
	if (wanttcp) {
		len += text_add(&bpfl, " )"); /* close udp & mbs & mbc clause */
	}
	if (!EMPTY(initiators) ||
	    !EMPTY(responders))
	{
		const char *or = "or", *lp = "(", *sep;
		endpoint_ptr ep;

		len += text_add(&bpfl, " and host");
		sep = lp;
		for (ep = HEAD(initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		for (ep = HEAD(responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		len += text_add(&bpfl, " )");
	}
	if (!EMPTY(not_initiators) ||
	    !EMPTY(not_responders))
	{
		const char *or = "or", *lp = "(", *sep;
		endpoint_ptr ep;

		len += text_add(&bpfl, " and not host");
		sep = lp;
		for (ep = HEAD(not_initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		for (ep = HEAD(not_responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		len += text_add(&bpfl, " )");
	}
	if (!EMPTY(vlans))
		len += text_add(&bpfl, " )");
	if (wanttcp)
		len += text_add(&bpfl, " )");
	if (wantfrags)
		len += text_add(&bpfl, " )");
	bpft = malloc(len + 1);
	assert(bpft != NULL);
	bpft[0] = '\0';
	for (text = HEAD(bpfl);
	     text != NULL;
	     text = NEXT(text, link))
		strcat(bpft, text->text);
	text_free(&bpfl);
	if (dumptrace >= 1)
		fprintf(stderr, "%s: \"%s\"\n", ProgramName, bpft);
}

static const char *
ia_str(iaddr ia) {
	static char ret[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

	(void) inet_ntop(ia.af, &ia.u, ret, sizeof ret);
	return (ret);
}

static int
ia_equal(iaddr x, iaddr y) {
	if (x.af != y.af)
		return FALSE;
	switch (x.af) {
	case AF_INET:
		return (x.u.a4.s_addr == y.u.a4.s_addr);
	case AF_INET6:
		return (memcmp(&x.u.a6, &y.u.a6, sizeof x.u.a6) == 0);
	}
	return FALSE;
}

static int
ep_present(const endpoint_list *list, iaddr ia) {
	endpoint_ptr ep;

	for (ep = HEAD(*list);
	     ep != NULL;
	     ep = NEXT(ep, link))
		if (ia_equal(ia, ep->ia))
			return TRUE;
	return (FALSE);
}

static size_t
text_add(text_list *list, const char *fmt, ...) {
	text_ptr text;
	va_list ap;
	int len;

	text = malloc(sizeof *text);
	assert(text != NULL);
	INIT_LINK(text, link);
	va_start(ap, fmt);
	len = vasprintf(&text->text, fmt, ap);
	assert(len >= 0);
	va_end(ap);
	APPEND(*list, text, link);
	return (len);
}

static void
text_free(text_list *list) {
	text_ptr text;

	while ((text = HEAD(*list)) != NULL) {
		UNLINK(*list, text, link);
		free(text);
	}
}

static void
open_pcaps(void) {
	mypcap_ptr mypcap;

	assert(!EMPTY(mypcaps));
	FD_ZERO(&mypcap_fdset);
	pcap_maxfd = 0;
	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link))
	{
		struct bpf_program bpfp;
#ifdef __APPLE__
		unsigned int ioarg = 1;
#endif

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
			fprintf(stderr, "%s: pcap warning: %s\n",
				ProgramName, errbuf);
		mypcap->dlt = pcap_datalink(mypcap->pcap);
		mypcap->fdes = pcap_get_selectable_fd(mypcap->pcap);
#ifdef __APPLE__
		ioctl(mypcap->fdes, BIOCIMMEDIATE, &ioarg);
#endif
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
	pcap_dead = pcap_open_dead(DLT_RAW, SNAPLEN);
}

static void
poll_pcaps(void) {
	mypcap_ptr mypcap;
	fd_set readfds;
	int n;

	do {
		memcpy(&readfds, &mypcap_fdset, sizeof(fd_set));
		n = select(pcap_maxfd+1, &readfds, NULL, NULL, NULL);
	} while (n < 0 && errno == EINTR && !main_exit);
	if (n < 0) {
		if (errno != EINTR)
			perror("select");
		main_exit = TRUE;
		return;
	}
	/* Poll them all. */
	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link))
	{
		n = pcap_dispatch(mypcap->pcap, -1, dl_pkt,
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
breakloop_pcaps(void) {
	mypcap_ptr mypcap;

	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link))
		pcap_breakloop(mypcap->pcap);
}

static void
close_pcaps(void) {
	mypcap_ptr mypcap;

	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link))
		pcap_close(mypcap->pcap);
	pcap_close(pcap_dead);
}

#define MAX_TCP_IDLE_TIME	600
#define MAX_TCP_IDLE_COUNT	4096
#define TCP_GC_TIME		60

static tcpstate_ptr
tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t) {
	static time_t next_gc = 0;
	tcpstate_ptr tcpstate;

	for (tcpstate = HEAD(tcpstates);
	     tcpstate != NULL;
	     tcpstate = NEXT(tcpstate, link))
	{
		if (ia_equal(tcpstate->saddr, from) &&
		    ia_equal(tcpstate->daddr, to) &&
		    tcpstate->sport == sport &&
		    tcpstate->dport == dport)
			break;
	}
	if (tcpstate != NULL) {
		tcpstate->last_use = t;
		if (tcpstate != HEAD(tcpstates)) {
			/* move to beginning of list */
			UNLINK(tcpstates, tcpstate, link);
			PREPEND(tcpstates, tcpstate, link);
		}
	}

	if (t >= next_gc || tcpstate_count > MAX_TCP_IDLE_COUNT) {
		/* garbage collect stale states */
		time_t min_last_use = t - MAX_TCP_IDLE_TIME;
		while ((tcpstate = TAIL(tcpstates)) &&
		    tcpstate->last_use < min_last_use)
		{
			UNLINK(tcpstates, tcpstate, link);
			tcpstate_count--;
		}
		next_gc = t + TCP_GC_TIME;
	}

	return tcpstate;
}

static tcpstate_ptr
tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport) {

	tcpstate_ptr tcpstate = malloc(sizeof *tcpstate);
	if (tcpstate == NULL) {
	    /* Out of memory; recycle the least recently used */
	    fprintf(stderr, "warning: out of memory, "
		"discarding some TCP state early\n");
	    tcpstate = TAIL(tcpstates);
	    assert(tcpstate != NULL);
	} else {
	    tcpstate_count++;
	}
	tcpstate->saddr = from;
	tcpstate->daddr = to;
	tcpstate->sport = sport;
	tcpstate->dport = dport;
	INIT_LINK(tcpstate, link);
	PREPEND(tcpstates, tcpstate, link);
	return tcpstate;
}

static void
dl_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	mypcap_ptr mypcap = (mypcap_ptr) user;
	size_t len = hdr->caplen;
	unsigned etype, vlan, pf;
	char descr[200];

	if (stop_time != 0 && hdr->ts.tv_sec >= stop_time) {
		breakloop_pcaps();
		main_exit = TRUE;
	}

	if (main_exit)
		return;

	/* If ever SNAPLEN wasn't big enough, we have no recourse. */
	if (hdr->len != hdr->caplen)
		return;

	/* Data link. */
	vlan = 0;
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
		MY_GET32(x, pkt);
		len -= NS_INT32SZ;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		break;
	    }
	case DLT_RAW: {
		if (len < 1)
			return;
		switch (*(const uint8_t *)pkt >> 4) {
		case 4:
			etype = ETHERTYPE_IP;
			break;
		case 6:
			etype = ETHERTYPE_IPV6;
			break;
		default:
			return;
		}
		break;
	    }
	case DLT_EN10MB: {
		const struct ether_header *ether;

		if (len < ETHER_HDR_LEN)
			return;
		ether = (const struct ether_header *) pkt;
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

	if (!EMPTY(vlans)) {
		vlan_ptr vl;

		for (vl = HEAD(vlans);
		     vl != NULL;
		     vl = NEXT(vl, link))
			if (vl->vlan == vlan || vl->vlan == 0)
				break;
		if (vl == NULL)
			return;
	}

	switch (etype) {
	case ETHERTYPE_IP:
		pf = PF_INET;
		break;
	case ETHERTYPE_IPV6:
		pf = PF_INET6;
		break;
	default:
		return;
	}

	if (preso) {
		char when[100], via[100];
		const struct tm *tm;
		time_t t;

		t = (time_t) hdr->ts.tv_sec;
		tm = gmtime(&t);
		strftime(when, sizeof when, "%Y-%m-%d %T", tm);
		strcpy(via, (mypcap->name == NULL)
				? "\"some interface\""
				: mypcap->name);
		if (vlan != 0)
			sprintf(via + strlen(via), " (vlan %u)", vlan);
		sprintf(descr, "[%lu] %s.%06lu [#%ld %s %u] \\\n",
			(u_long)len, when, (u_long)hdr->ts.tv_usec,
			(long)msgcount, via, vlan);
	} else {
		descr[0] = '\0';
	}
	network_pkt(descr, hdr->ts, pf, pkt, len);
}

/* Discard this packet.  If it's part of TCP stream, all subsequent pkts on
 * the same tcp stream will also be discarded. */
static void
discard(tcpstate_ptr tcpstate, const char *msg)
{
	if (dumptrace >= 3 && msg)
		fprintf(stderr, "%s\n", msg);
	if (tcpstate) {
		UNLINK(tcpstates, tcpstate, link);
		free(tcpstate);
		tcpstate_count--;
		return;
	}
}

static void
network_pkt(const char *descr, my_bpftimeval ts, unsigned pf,
	    const u_char *opkt, size_t olen)
{
	u_char pkt_copy[SNAPLEN], *pkt = pkt_copy;
	const u_char *dnspkt;
	unsigned proto, sport, dport;
	iaddr from, to, initiator, responder;
	struct ip6_hdr *ipv6;
	int response, isfrag;
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;
	tcpstate_ptr tcpstate = NULL;
	struct ip *ip;
	size_t len, dnslen;
	HEADER dns;

	/* Make a writable copy of the packet and use that copy from now on. */
	memcpy(pkt, opkt, len = olen);

	/* Network. */
	ip = NULL;
	ipv6 = NULL;
	isfrag = FALSE;
	sport = dport = 0;
	switch (pf) {
	case PF_INET: {
		unsigned offset;

		if (len < sizeof *ip)
			return;
		ip = (void *) pkt;
		if (ip->ip_v != IPVERSION)
			return;
		proto = ip->ip_p;
		memset(&from, 0, sizeof from);
		from.af = AF_INET;
		memcpy(&from.u.a4, &ip->ip_src, sizeof(struct in_addr));
		memset(&to, 0, sizeof to);
		to.af = AF_INET;
		memcpy(&to.u.a4, &ip->ip_dst, sizeof(struct in_addr));
		offset = ip->ip_hl << 2;
		if (len > ip->ip_len)	/* small IP packets have L2 padding */
			len = ip->ip_len;
		if (len <= offset)
			return;
		pkt += offset;
		len -= offset;
		offset = ntohs(ip->ip_off);
		if ((offset & IP_MF) != 0 ||
		    (offset & IP_OFFMASK) != 0)
		{
			if (wantfrags) {
				isfrag = TRUE;
				output(descr, from, to, isfrag, sport, dport, ts, pkt_copy, olen, NULL, 0);
				return;
			}
			return;
		}
		break;
	    }
	case PF_INET6: {
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

		memset(&from, 0, sizeof from);
		from.af = AF_INET6;
		memcpy(&from.u.a6, &ipv6->ip6_src, sizeof(struct in6_addr));
		memset(&to, 0, sizeof to);
		to.af = AF_INET6;
		memcpy(&to.u.a6, &ipv6->ip6_dst, sizeof(struct in6_addr));

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
			if (nexthdr == IPPROTO_FRAGMENT) {
				if (wantfrags) {
					isfrag = TRUE;
					output(descr, from, to, isfrag, sport, dport, ts, pkt_copy, olen, NULL, 0);
					return;
				}
				return;
			}

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
		dnspkt = pkt;
		dnslen = len;
		break;
	}
	case IPPROTO_TCP: {
		/* TCP processing.
		 * We need to capture enough to allow a later analysis to
		 * reassemble the TCP stream, but we don't want to keep all
		 * the state required to do reassembly here.
		 * When we get a SYN, we don't yet know if the DNS message
		 * will pass the filters, so we always output it, and also
		 * generate a tcpstate to keep track of the stream.  (An
		 * alternative would be to store the SYN packet on the
		 * tcpstate and not output it until a later packet passes the
		 * filter, but that would require more memory and would
		 * reorder packets in the pcap output.)
		 * When we get the _first_ DNS header on the stream, then we
		 * can apply the DNS header filters; if the packet passes, we
		 * output the packet and keep the tcpstate; if it fails, we
		 * discard the packet and the tcpstate.
		 * When we get any other packet with DNS payload, we output it
		 * only if there is a corresponding tcpstate indicating that
		 * the header passed the filters.
		 * Packets with no TCP payload (e.g., packets containing only
		 * an ACK) are discarded, since they carry no DNS information
		 * and are not needed for stream reassembly.
		 * FIN packets are always output to match the SYN, even if the
		 * DNS header failed the filter, to be friendly to later
		 * analysis programs that allocate state for each SYN.
		 * -- kkeys@caida.org
		 */
		unsigned offset;
		uint32_t seq;
		if (!wanttcp)
		    return;
		if (len < sizeof *tcp)
			return;
		tcp = (void *) pkt;
		switch (from.af) {
		case AF_INET:
		case AF_INET6:
			sport = ntohs(tcp->th_sport);
			dport = ntohs(tcp->th_dport);
			seq = ntohl(tcp->th_seq);
			break;
		default:
			abort();
		}
		offset = tcp->th_off * 4;
		pkt += offset;
		len -= offset;
#if 1
		tcpstate = tcpstate_find(from, to, sport, dport, ts.tv_sec);
		if (dumptrace >= 3) {
			fprintf(stderr, "%s: tcp pkt: %lu.%06lu [%4lu] ", ProgramName,
			    (u_long)ts.tv_sec, (u_long)ts.tv_usec, (u_long)len);
			fprintf(stderr, "%15s -> ", ia_str(from));
			fprintf(stderr, "%15s; ", ia_str(to));
			if (tcpstate)
			    fprintf(stderr, "want=%08x; ", tcpstate->start);
			else
			    fprintf(stderr, "no state; ");
			fprintf(stderr, "seq=%08x; ", seq);
		}
		if (tcp->th_flags & (TH_FIN | TH_RST)) {
		    /* Always output FIN and RST segments. */
		    if (dumptrace >= 3)
			fprintf(stderr, "FIN|RST\n");
		    output(descr, from, to, isfrag, sport, dport, ts,
			pkt_copy, olen, NULL, 0);
		    /* End of stream; deallocate the tcpstate. */
		    if (tcpstate) {
			UNLINK(tcpstates, tcpstate, link);
			free(tcpstate);
			tcpstate_count--;
		    }
		    return;
		}
		if (tcp->th_flags & TH_SYN) {
		    if (dumptrace >= 3)
			fprintf(stderr, "SYN\n");
		    /* Always output SYN segments. */
		    output(descr, from, to, isfrag, sport, dport, ts,
			pkt_copy, olen, NULL, 0);
		    if (tcpstate) {
#if 0
			/* Disabled because warning may scare user, and
			 * there's nothing else we can do anyway. */
			if (tcpstate->start == seq + 1) {
			    /* repeated SYN */
			} else {
			    /* Assume existing state is stale and recycle it. */
			    if (ts.tv_sec - tcpstate->last_use < MAX_TCP_IDLE_TIME)
				fprintf(stderr, "warning: recycling state for "
				    "duplicate tcp stream after only %ld "
				    "seconds idle\n",
				    (u_long)(ts.tv_sec - tcpstate->last_use));
			}
#endif
		    } else {
			/* create new tcpstate */
			tcpstate = tcpstate_new(from, to, sport, dport);
		    }
		    tcpstate->last_use = ts.tv_sec;
		    tcpstate->start = seq + 1; /* add 1 for the SYN */
		    tcpstate->maxdiff = 1;
		    tcpstate->dnslen = 0;
		    return;
		}
		if (tcpstate) {
		    uint32_t seqdiff = seq - tcpstate->start;
		    if (dumptrace >= 3)
			fprintf(stderr, "diff=%08x; ", seqdiff);
		    if (seqdiff == 0 && len > 2) {
			/* This is the first segment of the stream, and
			 * contains the dnslen and dns header, so we can
			 * filter on it. */
			if (dumptrace >= 3)
			    fprintf(stderr, "len+hdr\n");
			dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
			dnspkt = pkt + 2;
			if (dnslen > len - 2)
			    dnslen = len - 2;
			tcpstate->maxdiff = (uint32_t)len;
		    } else if (seqdiff == 0 && len == 2) {
			/* This is the first segment of the stream, but only
			 * contains the dnslen. */
			if (dumptrace >= 3)
			    fprintf(stderr, "len\n");
			tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
			tcpstate->maxdiff = (uint32_t)len;
			output(descr, from, to, isfrag, sport, dport, ts,
			    pkt_copy, olen, NULL, 0);
			return;
		    } else if ((seqdiff == 0 && len == 1) || seqdiff == 1) {
			/* shouldn't happen */
			discard(tcpstate, NULL);
			return;
		    } else if (seqdiff == 2) {
			/* This is not the first segment, but it does contain
			 * the first dns header, so we can filter on it. */
			if (dumptrace >= 3)
			    fprintf(stderr, "hdr\n");
			tcpstate->maxdiff = seqdiff + (uint32_t)len;
			dnslen = tcpstate->dnslen;
			dnspkt = pkt;
			if (dnslen == 0) /* we never received it */
			    dnslen = len;
			if (dnslen > len)
			    dnslen = len;
		    } else if (seqdiff > tcpstate->maxdiff + MAX_TCP_WINDOW) {
			/* This segment is outside the window. */
			if (dumptrace >= 3)
			    fprintf(stderr, "out of window\n");
			return;
		    } else if (len == 0) {
			/* No payload (e.g., an ACK) */
			if (dumptrace >= 3)
			    fprintf(stderr, "empty\n");
			return;
		    } else {
			/* non-first */
			if (dumptrace >= 3)
			    fprintf(stderr, "keep\n");
			if (tcpstate->maxdiff < seqdiff + (uint32_t)len)
			    tcpstate->maxdiff = seqdiff + (uint32_t)len;
			output(descr, from, to, isfrag, sport, dport, ts,
			    pkt_copy, olen, NULL, 0);
			return;
		    }
		} else {
		    if (dumptrace >= 3)
			fprintf(stderr, "no state\n");
		    /* There is no state for this stream.  Either we never saw
		     * a SYN for this stream, or we have already decided to
		     * discard this stream. */
		    return;
		}
#endif
		break;
	}
	default:
		return;
	}

	/* Application. */
	if (dnslen < sizeof dns) {
		discard(tcpstate, "too small");
		return;
	}
	memcpy(&dns, dnspkt, sizeof dns);

	/* Policy filtering. */
	if (dns.qr == 0 && dport == dns_port) {
		if ((dir_wanted & DIR_INITIATE) == 0) {
			discard(tcpstate, "unwanted dir=i");
			return;
		}
		initiator = from;
		responder = to;
		response = FALSE;
	} else if (dns.qr != 0 && sport == dns_port) {
		if ((dir_wanted & DIR_RESPONSE) == 0) {
			discard(tcpstate, "unwanted dir=r");
			return;
		}
		initiator = to;
		responder = from;
		response = TRUE;
	} else {
		discard(tcpstate, "unwanted direction/port");
		return;
	}
	if ((!EMPTY(initiators) &&
	     !ep_present(&initiators, initiator)) ||
	    (!EMPTY(responders) &&
	     !ep_present(&responders, responder)))
	{
		discard(tcpstate, "unwanted host");
		return;
	}
	if ((!EMPTY(not_initiators) &&
	     ep_present(&not_initiators, initiator)) ||
	    (!EMPTY(not_responders) &&
	     ep_present(&not_responders, responder)))
	{
		discard(tcpstate, "missing required host");
		return;
	}
	if (!(((msg_wanted & MSG_QUERY) != 0 && dns.opcode == ns_o_query) ||
	      ((msg_wanted & MSG_UPDATE) != 0 && dns.opcode == ns_o_update) ||
	      ((msg_wanted & MSG_NOTIFY) != 0 && dns.opcode == ns_o_notify)))
	{
		discard(tcpstate, "unwanted opcode");
		return;
	}
	if (response) {
		int match_tc = (dns.tc != 0 && err_wanted & ERR_TRUNC);
		int match_rcode = err_wanted & (ERR_RCODE_BASE << dns.rcode);

		if (!match_tc && !match_rcode) {
			discard(tcpstate, "unwanted error code");
			return;
		}
	}
#if HAVE_BINDLIB
	if (!EMPTY(myregexes)) {
		int match, negmatch;
		ns_msg msg;
		ns_sect s;

		match = FALSE;
		negmatch = FALSE;
		if (ns_initparse(dnspkt, dnslen, &msg) < 0) {
			discard(tcpstate, "failed parse");
			return;
		}
		for (s = ns_s_qd; s < ns_s_max && !match; s++) {
			char pres[SNAPLEN*4];
			const char *look;
			int count, n;
			ns_rr rr;

			count = ns_msg_count(msg, s);
			for (n = 0; n < count && !negmatch; n++) {
				myregex_ptr myregex;

				if (ns_parserr(&msg, s, n, &rr) < 0) {
					discard(tcpstate, "failed parse");
					return;
				}
				if (s == ns_s_qd) {
					look = ns_rr_name(rr);
				} else {
					if (ns_sprintrr(&msg, &rr, NULL, ".",
							pres, sizeof pres) < 0)
					{
						discard(tcpstate, "failed parse");
						return;
					}
					look = pres;
				}
				for (myregex = HEAD(myregexes);
				     myregex != NULL && !negmatch;
				     myregex = NEXT(myregex, link)) {
					if (((!match) || myregex->not) &&
					    regexec(&myregex->reg, look,
						    0, NULL, 0) == 0)
					{
						if (myregex->not) {
							negmatch = TRUE;
							match = FALSE;
						} else
							match = TRUE;
						if (dumptrace >= 2)
							fprintf(stderr,
						   "; \"%s\" ~ /%s/ %d %d\n",
								look,
								myregex->str,
								match,
								negmatch);
					}
				}
			}
		}
		if (!match) {
			discard(tcpstate, "failed regex match");
			return;
		}
	}
#endif

	/* Policy hiding. */
	if (end_hide != 0) {
		switch (from.af) {
		case AF_INET: {
			struct in_addr *init_addr, *resp_addr;
			uint16_t *init_port;

			if (dns.qr == 0) {
			    init_addr = &ip->ip_src;
			    resp_addr = &ip->ip_dst;
			    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
			} else {
			    init_addr = &ip->ip_dst;
			    resp_addr = &ip->ip_src;
			    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
				init_addr->s_addr = HIDE_INET;
				*init_port = htons(HIDE_PORT);
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
			    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
			} else {
			    init_addr = &ipv6->ip6_dst;
			    resp_addr = &ipv6->ip6_src;
			    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
                    		memcpy(init_addr, HIDE_INET6,
				       sizeof HIDE_INET6);
				*init_port = htons(HIDE_PORT);
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
	output(descr, from, to, isfrag, sport, dport, ts,
	    pkt_copy, olen, dnspkt, dnslen);
}

static void
output(const char *descr, iaddr from, iaddr to, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *dnspkt, unsigned dnslen)
{
	/* Output stage. */
	if (preso) {
		fputs(descr, stderr);
		if (isfrag) {
			fprintf(stderr, ";: [%s] ", ia_str(from));
			fprintf(stderr, "-> [%s] (frag)\n", ia_str(to));
		} else {
			fprintf(stderr, "\t[%s].%u ", ia_str(from), sport);
			fprintf(stderr, "[%s].%u ", ia_str(to), dport);
			if (dnspkt)
			    dump_dns(dnspkt, dnslen, stderr, "\\\n\t");
		}
		putc('\n', stderr);
	}
	if (dump_type != nowhere) {
		struct pcap_pkthdr h;

		if (next_interval != 0 && ts.tv_sec >= next_interval)
			dumper_close();
		if (dumper == NULL && dumper_open(ts))
			goto breakloop;
		memset(&h, 0, sizeof h);
		h.ts = ts;
		h.len = h.caplen = olen;
		pcap_dump((u_char *)dumper, &h, pkt_copy);
		if (flush)
			pcap_dump_flush(dumper);
	}
	if (limit_packets != 0U && msgcount == limit_packets) {
		if (dump_type == nowhere)
			goto breakloop;
		if (dumper != NULL && dumper_close())
			goto breakloop;
		msgcount = 0;
	}
	return;
 breakloop:
	breakloop_pcaps();
	main_exit = TRUE;
}

static int
dumper_open(my_bpftimeval ts) {
	const char *t = NULL;

	if (dump_type == to_stdout) {
		t = "-";
	} else {
		char sbuf[64];
		while (ts.tv_usec >= MILLION) {
			ts.tv_sec++;
			ts.tv_usec -= MILLION;
		}
		if (limit_seconds != 0U)
			next_interval = ts.tv_sec
				- (ts.tv_sec % limit_seconds)
				+ limit_seconds;
		strftime(sbuf, 64, "%Y%m%d.%H%M%S", gmtime((time_t *) &ts.tv_sec));
		if (asprintf(&dumpname, "%s.%s.%06lu",
			     dump_base, sbuf,
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
	if (limit_seconds != 0U) {
		struct timeval now;
		u_int seconds;
		time_t targ;

		gettimeofday(&now, NULL);
		while (now.tv_usec >= MILLION) {
			now.tv_sec++;
			now.tv_usec -= MILLION;
		}
		targ = (((now.tv_sec + (limit_seconds / 2))
			 / limit_seconds) + 1) * limit_seconds;
		assert(targ > now.tv_sec);
		seconds = targ - now.tv_sec;
		if (next_interval == 0) {
			alarm(seconds);
			alarm_set = TRUE;
		}
	}
	return (FALSE);
}

static void
do_pcap_stats()
{
	mypcap_ptr mypcap;
	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link)) {
		mypcap->ps0 = mypcap->ps1;
		pcap_stats(mypcap->pcap, &mypcap->ps1);
		fprintf(stderr, "%4s: %7u recv %7u drop %7u total\n",
			mypcap->name,
			mypcap->ps1.ps_recv - mypcap->ps0.ps_recv,
			mypcap->ps1.ps_drop - mypcap->ps0.ps_drop,
			mypcap->ps1.ps_recv + mypcap->ps1.ps_drop - mypcap->ps0.ps_recv - mypcap->ps0.ps_drop);
	}
}

static int
dumper_close(void) {
	int ret = FALSE;

	if (print_pcap_stats)
		do_pcap_stats();

	if (alarm_set) {
		alarm(0);
		alarm_set = FALSE;
	}
	pcap_dump_close(dumper); dumper = FALSE;
	if (dump_type == to_stdout) {
		assert(dumpname == NULL);
		assert(dumpnamepart == NULL);
		if (dumptrace >= 1)
			fprintf(stderr, "%s: breaking\n", ProgramName);
		ret = TRUE;
	} else {
		char *cmd = NULL;;

		if (dumptrace >= 1)
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
		if (kick_cmd == NULL)
			ret = TRUE;
	}
	return (ret);
}

static void
sigclose(int signum) {
	if (signum == SIGALRM)
		alarm_set = FALSE;
	if (dumper_close())
		breakloop_pcaps();
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
