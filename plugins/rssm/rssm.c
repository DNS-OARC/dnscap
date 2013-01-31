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

#include "../../dnscap_common.h"

#include "hashtbl.h"

static logerr_t *my_logerr;
static my_bpftimeval open_ts;
static my_bpftimeval last_ts;
static const char *prefix = "rssm";

output_t rssm_output;

#define MAX_SIZE_INDEX 4096
#define MSG_SIZE_SHIFT 4
#define MAX_TBL_ADDRS 1000000

typedef struct {
	hashtbl *tbl;
	iaddr addrs[MAX_TBL_ADDRS];
	uint64_t count[MAX_TBL_ADDRS];
	unsigned int num_addrs;
} my_hashtbl;

struct {
	uint64_t dns_udp_queries_received_ipv4;
	uint64_t dns_udp_queries_received_ipv6;
	uint64_t dns_tcp_queries_received_ipv4;
	uint64_t dns_tcp_queries_received_ipv6;
	uint64_t dns_udp_responses_received_ipv4;
	uint64_t dns_udp_responses_received_ipv6;
	uint64_t dns_tcp_responses_received_ipv4;
	uint64_t dns_tcp_responses_received_ipv6;
	uint64_t query_size[MAX_SIZE_INDEX];
	uint64_t response_size[MAX_SIZE_INDEX];
	my_hashtbl ht_ipv4_full;
	my_hashtbl ht_ipv6_full;
	my_hashtbl ht_ipv6_aggr;
} counts;


#if 0
static char *
iaddr_ntop(const iaddr *ia)
{
	static char bufs[10][256];
	static int idx = 0;
	if (10 == idx)
		idx = 0;
	inet_ntop(ia->af, &ia->u, bufs[idx], 256);
	return bufs[idx];
}
#endif

static unsigned int
iaddr_hash(const iaddr *ia)
{
	if (AF_INET == ia->af)
		return ia->u.a4.s_addr >> 8;
	else if (AF_INET6 == ia->af) {
		uint16_t *h = (uint16_t*) &ia->u;
		return h[2] + h[3] + h[4];
	} else
		return 0;
}

static unsigned int
iaddr_cmp(const iaddr *a, const iaddr *b)
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
rssm_usage()
{
	fprintf(stderr,
		"\nrssm.so options:\n"
		"\t-w <base>  write to <base>.<timesec>.<timeusec>\n"
		);
}

void
rssm_getopt(int *argc, char **argv[])
{
	int c;
	while ((c = getopt(*argc, *argv, "w:")) != EOF) {
		switch(c) {
		case 'w':
			prefix = strdup(optarg);
			break;
		default:
			rssm_usage();
			exit(1);
		}
	}
}

int
rssm_start(logerr_t *a_logerr)
{
	my_logerr = a_logerr;
	return 0;
}

void
rssm_stop()
{
}

int
rssm_open(my_bpftimeval ts)
{
	open_ts = ts;
	if (counts.ht_ipv4_full.tbl)
		hash_destroy(counts.ht_ipv4_full.tbl);
	if (counts.ht_ipv6_full.tbl)
		hash_destroy(counts.ht_ipv6_full.tbl);
	if (counts.ht_ipv6_aggr.tbl)
		hash_destroy(counts.ht_ipv6_aggr.tbl);
	memset(&counts, 0, sizeof(counts));
	counts.ht_ipv4_full.tbl = hash_create(65536, (hashfunc*) iaddr_hash, (hashkeycmp*) iaddr_cmp, 0);
	counts.ht_ipv6_full.tbl = hash_create(65536, (hashfunc*) iaddr_hash, (hashkeycmp*) iaddr_cmp, 0);
	counts.ht_ipv6_aggr.tbl = hash_create(65536, (hashfunc*) iaddr_hash, (hashkeycmp*) iaddr_cmp, 0);
	return 0;
}

/*
 * Fork a separate process so that we don't block the main dnscap.  Use double-fork
 * to avoid zombies for the main dnscap process.
 */
int
rssm_close()
{
	FILE *fp;
	char sbuf[265];
	char *tbuf;
	pid_t pid;
	int i;
	pid = fork();
	if (pid < 0) {
		my_logerr("rssm.so: fork: %s", strerror(errno));
		return 1;
	} else if (pid) {
		/* parent */
		waitpid(pid, NULL, 0);
		return 0;
	}
	/* 1st gen child continues */
	pid = fork();
	if (pid < 0) {
		my_logerr("rssm.so: fork: %s", strerror(errno));
		return 1;
	} else if (pid) {
		/* 1st gen child exits */
		exit(0);
	}
	/* grandchild (2nd gen) continues */
	strftime(sbuf, sizeof(sbuf), "%Y%m%d.%H%M%S", gmtime((time_t *) &open_ts.tv_sec));
	asprintf(&tbuf, "%s.%s.%06lu", prefix, sbuf, (u_long) open_ts.tv_usec);
	fp = fopen(tbuf, "w");
	if (!fp) {
		my_logerr("%s: %s", sbuf, strerror(errno));
		return 1;
	}
	fprintf(fp, "first-packet-time %lu\n", open_ts.tv_sec);
	fprintf(fp, "last-packet-time %lu\n", last_ts.tv_sec);
	fprintf(fp, "dns-udp-queries-received-ipv4 %"PRIu64"\n", counts.dns_udp_queries_received_ipv4);
	fprintf(fp, "dns-udp-queries-received-ipv6 %"PRIu64"\n", counts.dns_udp_queries_received_ipv6);
	fprintf(fp, "dns-tcp-queries-received-ipv4 %"PRIu64"\n", counts.dns_tcp_queries_received_ipv4);
	fprintf(fp, "dns-tcp-queries-received-ipv6 %"PRIu64"\n", counts.dns_tcp_queries_received_ipv6);
	fprintf(fp, "dns-udp-responses-received-ipv4 %"PRIu64"\n", counts.dns_udp_responses_received_ipv4);
	fprintf(fp, "dns-udp-responses-received-ipv6 %"PRIu64"\n", counts.dns_udp_responses_received_ipv6);
	fprintf(fp, "dns-tcp-responses-received-ipv4 %"PRIu64"\n", counts.dns_tcp_responses_received_ipv4);
	fprintf(fp, "dns-tcp-responses-received-ipv6 %"PRIu64"\n", counts.dns_tcp_responses_received_ipv6);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.query_size[i])
			fprintf(fp, "dns-query-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.query_size[i]);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.response_size[i])
			fprintf(fp, "dns-response-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.response_size[i]);
	fprintf(fp, "num-sources-ipv4 %d\n", hash_count(counts.ht_ipv4_full.tbl));
	fprintf(fp, "num-sources-ipv6 %d\n", hash_count(counts.ht_ipv6_full.tbl));
	fprintf(fp, "num-sources-ipv6-aggregate %d\n", hash_count(counts.ht_ipv6_aggr.tbl));
	fclose(fp);
	exit(0);
}

static void
hash_find_or_add(iaddr ia, my_hashtbl *t)
{
	uint16_t *c = hash_find(&ia, t->tbl);
	if (c) {
		(*c)++;
		return;
	}
	if (t->num_addrs == MAX_TBL_ADDRS)
		return;
	t->addrs[t->num_addrs] = ia;
	t->count[t->num_addrs]++;
	hash_add(&t->addrs[t->num_addrs], &t->count[t->num_addrs], t->tbl);
	t->num_addrs++;
}

void
rssm_output(const char *descr, iaddr from, iaddr to, uint8_t proto, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *dnspkt, unsigned dnslen)
{
	if (!dnspkt)
		return;
	last_ts = ts;
	dnslen >>= MSG_SIZE_SHIFT;
	if (dnslen >= MAX_SIZE_INDEX)
		dnslen = MAX_SIZE_INDEX-1;
	HEADER *dns = (HEADER *) dnspkt;
	if (0 == dns->qr) {
		counts.query_size[dnslen]++;
		if (AF_INET == from.af) {
			hash_find_or_add(from, &counts.ht_ipv4_full);
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_queries_received_ipv4++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_queries_received_ipv4++;
			}
		} else if (AF_INET6 == from.af) {
			iaddr aggr = from;
			void *z = &aggr.u;
			memset(z+8, 0, 8);
			hash_find_or_add(from, &counts.ht_ipv6_full);
			hash_find_or_add(aggr, &counts.ht_ipv6_aggr);
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_queries_received_ipv6++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_queries_received_ipv6++;
			}
		}
	} else {
		counts.response_size[dnslen]++;
		if (AF_INET == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_responses_received_ipv4++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_responses_received_ipv4++;
			}
		} else if (AF_INET6 == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_responses_received_ipv6++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_responses_received_ipv6++;
			}
		}
	}
}
