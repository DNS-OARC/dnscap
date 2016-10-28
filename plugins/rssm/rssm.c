/*
 * Copyright (c) 2016, OARC, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <arpa/nameser.h>
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <ldns/ldns.h>

#include "dnscap_common.h"

#include "hashtbl.h"

static logerr_t *logerr;
static my_bpftimeval open_ts;
static my_bpftimeval clos_ts;
#define COUNTS_PREFIX_DEFAULT "rssm"
static char *counts_prefix = 0;
static char *sources_prefix = 0;

output_t rssm_output;

#define MAX_SIZE_INDEX 4096
#define MSG_SIZE_SHIFT 4
#define MAX_TBL_ADDRS 2000000
#define MAX_RCODE (1<<12)

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
	uint64_t dns_udp_responses_sent_ipv4;
	uint64_t dns_udp_responses_sent_ipv6;
	uint64_t dns_tcp_responses_sent_ipv4;
	uint64_t dns_tcp_responses_sent_ipv6;
	uint64_t udp_query_size[MAX_SIZE_INDEX];
	uint64_t tcp_query_size[MAX_SIZE_INDEX];
	uint64_t udp_response_size[MAX_SIZE_INDEX];
	uint64_t tcp_response_size[MAX_SIZE_INDEX];
	uint64_t rcodes[MAX_RCODE];
	my_hashtbl sources;
} counts;


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
		"\t-w <name>  write basic counters to <name>.<timesec>.<timeusec>\n"
		"\t-s <name>  write source IPs to <name>.<timesec>.<timeusec>\n"
		);
}

void
rssm_getopt(int *argc, char **argv[])
{
	int c;
	while ((c = getopt(*argc, *argv, "w:s:")) != EOF) {
		switch(c) {
		case 'w':
		    if (counts_prefix)
		        free(counts_prefix);
			counts_prefix = strdup(optarg);
			break;
		case 's':
		    if (sources_prefix)
		        free(sources_prefix);
			sources_prefix = strdup(optarg);
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
	logerr = a_logerr;
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
	if (counts.sources.tbl)
		hash_destroy(counts.sources.tbl);
	memset(&counts, 0, sizeof(counts));
	counts.sources.tbl = hash_create(65536, (hashfunc*) iaddr_hash, (hashkeycmp*) iaddr_cmp, 0);
	return 0;
}

void
rssm_save_counts(const char *sbuf)
{
	FILE *fp;
	int i;
	char *tbuf = 0;
	i = asprintf(&tbuf, "%s.%s.%06lu", counts_prefix ? counts_prefix : COUNTS_PREFIX_DEFAULT, sbuf, (u_long) open_ts.tv_usec);
	if (i < 1 || !tbuf) {
		logerr("asprintf: out of memory");
		return;
	}
	fp = fopen(tbuf, "w");
	if (!fp) {
		logerr("%s: %s", sbuf, strerror(errno));
		return;
	}
	fprintf(fp, "first-packet-time %lu\n", open_ts.tv_sec);
	fprintf(fp, "last-packet-time %lu\n", clos_ts.tv_sec);
	fprintf(fp, "dns-udp-queries-received-ipv4 %"PRIu64"\n", counts.dns_udp_queries_received_ipv4);
	fprintf(fp, "dns-udp-queries-received-ipv6 %"PRIu64"\n", counts.dns_udp_queries_received_ipv6);
	fprintf(fp, "dns-tcp-queries-received-ipv4 %"PRIu64"\n", counts.dns_tcp_queries_received_ipv4);
	fprintf(fp, "dns-tcp-queries-received-ipv6 %"PRIu64"\n", counts.dns_tcp_queries_received_ipv6);
	fprintf(fp, "dns-udp-responses-sent-ipv4 %"PRIu64"\n", counts.dns_udp_responses_sent_ipv4);
	fprintf(fp, "dns-udp-responses-sent-ipv6 %"PRIu64"\n", counts.dns_udp_responses_sent_ipv6);
	fprintf(fp, "dns-tcp-responses-sent-ipv4 %"PRIu64"\n", counts.dns_tcp_responses_sent_ipv4);
	fprintf(fp, "dns-tcp-responses-sent-ipv6 %"PRIu64"\n", counts.dns_tcp_responses_sent_ipv6);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.udp_query_size[i])
			fprintf(fp, "dns-udp-query-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.udp_query_size[i]);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.tcp_query_size[i])
			fprintf(fp, "dns-tcp-query-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.tcp_query_size[i]);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.udp_response_size[i])
			fprintf(fp, "dns-udp-response-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.udp_response_size[i]);
	for (i=0; i<MAX_SIZE_INDEX; i++)
		if (counts.tcp_response_size[i])
			fprintf(fp, "dns-tcp-response-size %d-%d %"PRIu64"\n",
				i<<MSG_SIZE_SHIFT,
				((i+1)<<MSG_SIZE_SHIFT)-1,
				counts.tcp_response_size[i]);
	for (i=0; i<MAX_RCODE; i++)
		if (counts.rcodes[i])
			fprintf(fp, "dns-rcode %d %"PRIu64"\n",
				i, counts.rcodes[i]);
	fprintf(fp, "num-sources %u\n", counts.sources.num_addrs);
	fclose(fp);
	free(tbuf);
}

void
rssm_save_sources(const char *sbuf)
{
	FILE *fp;
	char *tbuf = 0;
	int i;
	i = asprintf(&tbuf, "%s.%s.%06lu", sources_prefix, sbuf, (u_long) open_ts.tv_usec);
	if (i < 1 || !tbuf) {
		logerr("asprintf: out of memory");
		return;
	}
	fp = fopen(tbuf, "w");
	if (!fp) {
		logerr("%s: %s", tbuf, strerror(errno));
		return;
	}
	for (i = 0; i < counts.sources.num_addrs; i++) {
		fprintf(fp, "%s %"PRIu64"\n", iaddr_ntop(&counts.sources.addrs[i]), counts.sources.count[i]);
	}
	fclose(fp);
	free(tbuf);
}

/*
 * Fork a separate process so that we don't block the main dnscap.  Use double-fork
 * to avoid zombies for the main dnscap process.
 */
int
rssm_close(my_bpftimeval ts)
{
	char sbuf[265];
	pid_t pid;
	pid = fork();
	if (pid < 0) {
		logerr("rssm.so: fork: %s", strerror(errno));
		return 1;
	} else if (pid) {
		/* parent */
		waitpid(pid, NULL, 0);
		return 0;
	}
	/* 1st gen child continues */
	pid = fork();
	if (pid < 0) {
		logerr("rssm.so: fork: %s", strerror(errno));
		return 1;
	} else if (pid) {
		/* 1st gen child exits */
		exit(0);
	}
	/* grandchild (2nd gen) continues */
	strftime(sbuf, sizeof(sbuf), "%Y%m%d.%H%M%S", gmtime((time_t *) &open_ts.tv_sec));
	clos_ts = ts;
	rssm_save_counts(sbuf);
	if (sources_prefix)
		rssm_save_sources(sbuf);
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
rssm_output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, const unsigned olen,
    const u_char *payload, const unsigned payloadlen)
{
	if (!(flags & DNSCAP_OUTPUT_ISDNS))
		return;
	unsigned dnslen = payloadlen >> MSG_SIZE_SHIFT;
	if (dnslen >= MAX_SIZE_INDEX)
		dnslen = MAX_SIZE_INDEX-1;
	HEADER *dns = (HEADER *) payload;
	if (0 == dns->qr) {
		hash_find_or_add(from, &counts.sources);
		if (IPPROTO_UDP == proto) {
			counts.udp_query_size[dnslen]++;
		} else if (IPPROTO_TCP == proto) {
			counts.tcp_query_size[dnslen]++;
		}
		if (AF_INET == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_queries_received_ipv4++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_queries_received_ipv4++;
			}
		} else if (AF_INET6 == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_queries_received_ipv6++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_queries_received_ipv6++;
			}
		}
	} else {
		uint16_t rcode = dns->rcode;
		if (IPPROTO_UDP == proto) {
			counts.udp_response_size[dnslen]++;
		} else if (IPPROTO_TCP == proto) {
			counts.tcp_response_size[dnslen]++;
		}
		if (AF_INET == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_responses_sent_ipv4++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_responses_sent_ipv4++;
			}
		} else if (AF_INET6 == from.af) {
			if (IPPROTO_UDP == proto) {
				counts.dns_udp_responses_sent_ipv6++;
			} else if (IPPROTO_TCP == proto) {
				counts.dns_tcp_responses_sent_ipv6++;
			}
		}
		if (dns->arcount) {
			ldns_pkt *pkt = 0;
			if (LDNS_STATUS_OK == ldns_wire2pkt(&pkt, payload, payloadlen)) {
				rcode |= ((uint16_t) ldns_pkt_edns_extended_rcode(pkt) << 4);
				ldns_pkt_free(pkt);
			}
		}
		counts.rcodes[rcode]++;
	}
}
