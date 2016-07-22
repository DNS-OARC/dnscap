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

#include <ldns/ldns.h>

#include "dnscap_common.h"

#include "hashtbl.h"

static logerr_t *logerr;
static my_bpftimeval open_ts;
static const char *report_zone = "rzkeychange.verisignlabs.com";

output_t rzkeychange_output;

#define MAX_TBL_ADDRS 2000000

typedef struct {
    hashtbl *tbl;
    iaddr addrs[MAX_TBL_ADDRS];
    unsigned int num_addrs;
}      my_hashtbl;

struct {
    uint64_t dnskey;
    uint64_t tc_bit;
    uint64_t tcp;
    uint64_t total;
    my_hashtbl sources;
}      counts;


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




void
rzkeychange_usage()
{
    fprintf(stderr,
	"\nrzkeychange.so options:\n"
	"\t-z <zone>  Report counters to DNS zone <zone>\n"

    );
}

void
rzkeychange_getopt(int *argc, char **argv[])
{
    int c;
    while ((c = getopt(*argc, *argv, "z:")) != EOF) {
	switch (c) {
	case 'z':
	    report_zone = strdup(optarg);
	    break;
	default:
	    rzkeychange_usage();
	    exit(1);
	}
    }
}

int
rzkeychange_start(logerr_t * a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void
rzkeychange_stop()
{
}

int
rzkeychange_open(my_bpftimeval ts)
{
    open_ts = ts;
    if (counts.sources.tbl)
	hash_destroy(counts.sources.tbl);
    memset(&counts, 0, sizeof(counts));
    counts.sources.tbl = hash_create(65536, (hashfunc *) iaddr_hash, (hashkeycmp *) iaddr_cmp, 0);
    return 0;
}

void
rzkeychange_submit_counts(void)
{
    char qname[256];
    snprintf(qname, sizeof(qname), "%lu-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64".%s",
	open_ts.tv_sec,
	counts.total,
	counts.dnskey,
	counts.tcp,
	counts.tc_bit,
	report_zone);
    fputs(qname, stderr);
    fputc('\n', stderr);
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
	logerr("rzkeychange.so: fork: %s", strerror(errno));
	return 1;
    } else if (pid) {
	/* parent */
	waitpid(pid, NULL, 0);
	return 0;
    }
    /* 1st gen child continues */
    pid = fork();
    if (pid < 0) {
	logerr("rzkeychange.so: fork: %s", strerror(errno));
	return 1;
    } else if (pid) {
	/* 1st gen child exits */
	exit(0);
    }
    /* grandchild (2nd gen) continues */
    rzkeychange_submit_counts();
    exit(0);
}

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

void
rzkeychange_output(const char *descr, iaddr from, iaddr to, uint8_t proto, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char * pkt_copy, unsigned olen,
    const u_char * dnspkt, unsigned dnslen)
{
    ldns_pkt *pkt = 0;
    ldns_rr_list *question_rr_list = 0;
    ldns_rr *question_rr = 0;
    if (!dnspkt)
	return;
    if (LDNS_STATUS_OK != ldns_wire2pkt(&pkt, dnspkt, dnslen))
	return;
    if (0 == ldns_pkt_qr(pkt))
	goto done;
    counts.total++;
    hash_find_or_add(from, &counts.sources);
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
