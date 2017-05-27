#define COUNT_SOURCES 0

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <arpa/nameser.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

#include <ldns/ldns.h>

#include "dnscap_common.h"

#if COUNT_SOURCES
#include "hashtbl.h"
#endif

static plugin_callbacks *callbacks = 0;
static my_bpftimeval open_ts = {0,0};
static my_bpftimeval clos_ts = {0,0};
static const char *report_zone = 0;
static const char *report_server = 0;
static const char *report_node = 0;
static unsigned short resolver_port = 0;
static unsigned int resolver_use_tcp = 0;
static ldns_resolver *res;

plugin_start_t rzkeychange_start;
plugin_stop_t rzkeychange_stop;
plugin_open_t rzkeychange_open;
plugin_close_t rzkeychange_close;
plugin_output_t rzkeychange_output;
plugin_getopt_t rzkeychange_getopt;
plugin_usage_t rzkeychange_usage;

#define MAX_TBL_ADDRS 2000000

#if COUNT_SOURCES
typedef struct {
    hashtbl *tbl;
    iaddr addrs[MAX_TBL_ADDRS];
    unsigned int num_addrs;
}      my_hashtbl;
#endif

struct {
    uint64_t dnskey;
    uint64_t tc_bit;
    uint64_t tcp;
    uint64_t icmp_unreach_frag;
    uint64_t icmp_timxceed_reass;
    uint64_t icmp_timxceed_intrans;
    uint64_t total;
#if COUNT_SOURCES
    my_hashtbl sources;
#endif
}      counts;

#define MAX_NAMESERVERS 10
static unsigned int num_ns_addrs = 0;
static char *ns_addrs[MAX_NAMESERVERS];


#if COUNT_SOURCES
static unsigned int
iaddr_hash(const iaddr * ia)
{
    if (AF_INET == ia->af)
	return ia->u.a4.s_addr >> 8;
    else if (AF_INET6 == ia->af) {
	uint16_t *h = (uint16_t *) & ia->u;
	return h[2] + h[3] + h[4];
    } else
	return 0;
}

static unsigned int
iaddr_cmp(const iaddr * a, const iaddr * b)
{
    if (a->af == b->af) {
	if (AF_INET == a->af)
	    return memcmp(&a->u, &b->u, 4);
	if (AF_INET6 == a->af)
	    return memcmp(&a->u, &b->u, 16);
	return 0;
    }
    if (a->af < b->af)
	return -1;
    return 1;
}
#endif



void
rzkeychange_usage()
{
    fprintf(stderr,
	"\nrzkeychange.so options:\n"
	"\t-z <zone>    Report counters to DNS zone <zone> (required)\n"
	"\t-s <server>  Data is from server <server> (required)\n"
	"\t-n <node>    Data is from site/node <node> (required)\n"
	"\t-a <addr>	Send DNS queries to this addr\n"
	"\t-p <port>    Send DNS queries to this port\n"
	"\t-t           Use TCP for DNS queries\n"
    );
}

void
rzkeychange_getopt(int *argc, char **argv[])
{
    int c;
    while ((c = getopt(*argc, *argv, "a:n:p:s:tz:")) != EOF) {
	switch (c) {
	case 'n':
	    report_node = strdup(optarg);
	    break;
	case 's':
	    report_server = strdup(optarg);
	    break;
	case 'z':
	    report_zone = strdup(optarg);
	    break;
	case 'a':
	    if (num_ns_addrs < MAX_NAMESERVERS) {
		ns_addrs[num_ns_addrs] = strdup(optarg);
		num_ns_addrs++;
	    }
	    break;
	case 'p':
	    resolver_port = strtoul(optarg, 0, 10);
	    break;
	case 't':
	    resolver_use_tcp = 1;
	    break;
	default:
	    rzkeychange_usage();
	    exit(1);
	}
    }
    if (!report_zone || !report_server || !report_node) {
	rzkeychange_usage();
	exit(1);
    }
}

ldns_pkt *
dns_query(const char *name, ldns_rr_type type)
{
    fprintf(stderr, "%s\n", name);
    ldns_rdf *domain = ldns_dname_new_frm_str(name);
    if (0 == domain) {
	fprintf(stderr, "bad query name: '%s'\n", name);
	exit(1);
    }
    ldns_pkt *pkt = ldns_resolver_query(res,
	domain,
	type,
	LDNS_RR_CLASS_IN,
	LDNS_RD);
    ldns_rdf_deep_free(domain);
    return pkt;
}

static void
add_resolver_nameserver(const char *s)
{
    ldns_rdf *nsaddr;
    fprintf(stderr, "adding nameserver '%s' to resolver config\n", s);
    if (strchr(s, ':'))
	nsaddr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, s);
    else
	nsaddr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, s);
    if (!nsaddr) {
	callbacks->logerr("rzkeychange.so: invalid IP address '%s'", s);
	exit(1);
    }
    assert(LDNS_STATUS_OK == ldns_resolver_push_nameserver(res, nsaddr));
}

int
rzkeychange_start(plugin_callbacks * the_callbacks)
{
    ldns_pkt *pkt;
    struct timeval to;
    char qname[256];
    callbacks = the_callbacks;
    if (LDNS_STATUS_OK != ldns_resolver_new_frm_file(&res, NULL)) {
	fprintf(stderr, "Failed to initialize ldns resolver\n");
	exit(1);
    }
    if (num_ns_addrs) {
	unsigned int i;
	ldns_resolver_set_nameserver_count(res, 0);
	for (i=0; i<num_ns_addrs; i++)
	    add_resolver_nameserver(ns_addrs[i]);
    }
    if (0 == ldns_resolver_nameserver_count(res))
	add_resolver_nameserver("127.0.0.1");
    if (resolver_port)
	ldns_resolver_set_port(res, resolver_port);
    if (resolver_use_tcp)
	ldns_resolver_set_usevc(res, 1);
    //
    fprintf(stderr, "Testing reachability of zone '%s'\n", report_zone);
    pkt = dns_query(report_zone, LDNS_RR_TYPE_TXT);
    if (!pkt) {
	fprintf(stderr, "Test of zone '%s' failed\n", report_zone);
	exit(1);
    }
    if (0 != ldns_pkt_get_rcode(pkt)) {
    	fprintf(stderr, "Query to zone '%s' returned rcode %d\n", report_zone, ldns_pkt_get_rcode(pkt));
	exit(1);
    }
    fprintf(stderr, "Success.\n");
    if (pkt)
	ldns_pkt_free(pkt);
    /*
     * For all subsequent queries we don't actually care about the response
     * and don't wait to wait very long for it so  the timeout is set really low.
     */
    to.tv_sec = 0;
    to.tv_usec = 500000;
    ldns_resolver_set_timeout(res, to);
    snprintf(qname, sizeof(qname), "ts-elapsed-tot-dnskey-tcp-tc-unreachfrag-texcfrag-texcttl.%s.%s.%s", report_node, report_server, report_zone);
    pkt = dns_query(qname, LDNS_RR_TYPE_TXT);
    if (pkt)
	ldns_pkt_free(pkt);
    return 0;
}

void
rzkeychange_stop()
{
}

int
rzkeychange_open(my_bpftimeval ts)
{
    open_ts = clos_ts.tv_sec ? clos_ts : ts;
#if COUNT_SOURCES
    if (counts.sources.tbl)
	hash_destroy(counts.sources.tbl);
#endif
    memset(&counts, 0, sizeof(counts));
#if COUNT_SOURCES
    counts.sources.tbl = hash_create(65536, (hashfunc *) iaddr_hash, (hashkeycmp *) iaddr_cmp, 0);
#endif
    return 0;
}

void
rzkeychange_submit_counts(void)
{
    char qname[256];
    double elapsed = (double) clos_ts.tv_sec - (double) open_ts.tv_sec + 0.000001 * clos_ts.tv_usec - 0.000001 * open_ts.tv_usec;
    snprintf(qname, sizeof(qname), "%lu-%u-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64".%s.%s.%s",
	open_ts.tv_sec,
	(unsigned int) (elapsed + 0.5),
	counts.total,
	counts.dnskey,
	counts.tcp,
	counts.tc_bit,
	counts.icmp_unreach_frag,
	counts.icmp_timxceed_reass,
	counts.icmp_timxceed_intrans,
	report_node,
	report_server,
	report_zone);
    dns_query(qname, LDNS_RR_TYPE_TXT);
    /* normally we would free any return packet, but this process is about to exit */
}

/*
 * Fork a separate process so that we don't block the main dnscap.  Use
 * double-fork to avoid zombies for the main dnscap process.
 */
int
rzkeychange_close(my_bpftimeval ts)
{
    pid_t pid;
    pid = fork();
    if (pid < 0) {
	callbacks->logerr("rzkeychange.so: fork: %s", strerror(errno));
	return 1;
    } else if (pid) {
	/* parent */
	waitpid(pid, NULL, 0);
	return 0;
    }
    /* 1st gen child continues */
    pid = fork();
    if (pid < 0) {
	callbacks->logerr("rzkeychange.so: fork: %s", strerror(errno));
	return 1;
    } else if (pid) {
	/* 1st gen child exits */
	exit(0);
    }
    /* grandchild (2nd gen) continues */
    clos_ts = ts;
    rzkeychange_submit_counts();
    exit(0);
}

#if COUNT_SOURCES
static void
hash_find_or_add(iaddr ia, my_hashtbl * t)
{
    uint16_t *c = hash_find(&ia, t->tbl);
    if (c)
	return;
    if (t->num_addrs == MAX_TBL_ADDRS)
	return;
    t->addrs[t->num_addrs] = ia;
    hash_add(&t->addrs[t->num_addrs], 0, t->tbl);
    t->num_addrs++;
}
#endif

void
rzkeychange_output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char * pkt_copy, const unsigned olen,
    const u_char * payload, const unsigned payloadlen)
{
    ldns_pkt *pkt = 0;
    ldns_rr_list *question_rr_list = 0;
    ldns_rr *question_rr = 0;
    if (!(flags & DNSCAP_OUTPUT_ISDNS)) {
	if (IPPROTO_ICMP == proto && payloadlen >= 4) {
	    struct icmp *icmp;
	    if (!callbacks->is_responder(to))
		goto done;
	    icmp = (void *) payload;
	    if (ICMP_UNREACH == icmp->icmp_type) {
		if (ICMP_UNREACH_NEEDFRAG == icmp->icmp_code)
		    counts.icmp_unreach_frag++;
	    } else if (ICMP_TIMXCEED == icmp->icmp_type) {
		if (ICMP_TIMXCEED_INTRANS == icmp->icmp_code)
		    counts.icmp_timxceed_intrans++;
		else if (ICMP_TIMXCEED_REASS == icmp->icmp_code)
		    counts.icmp_timxceed_reass++;
	    }
	}
	goto done;
    }
    if (LDNS_STATUS_OK != ldns_wire2pkt(&pkt, payload, payloadlen))
	return;
    if (0 == ldns_pkt_qr(pkt))
	goto done;
    counts.total++;
#if COUNT_SOURCES
    hash_find_or_add(from, &counts.sources);
#endif
    if (IPPROTO_UDP == proto) {
	if (0 != ldns_pkt_tc(pkt))
	    counts.tc_bit++;
    } else if (IPPROTO_TCP == proto) {
	counts.tcp++;
    }
    if (LDNS_PACKET_QUERY != ldns_pkt_get_opcode(pkt))
	goto done;
    question_rr_list = ldns_pkt_question(pkt);
    if (0 == question_rr_list)
	goto done;
    question_rr = ldns_rr_list_rr(question_rr_list, 0);
    if (0 == question_rr)
	goto done;
    if (LDNS_RR_CLASS_IN == ldns_rr_get_class(question_rr))
	if (LDNS_RR_TYPE_DNSKEY == ldns_rr_get_type(question_rr))
	    counts.dnskey++;
done:
    ldns_pkt_free(pkt);
}
