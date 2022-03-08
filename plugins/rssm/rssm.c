/*
 * Copyright (c) 2016-2022, OARC, Inc.
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
#include <netinet/in.h>
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

static logerr_t*     logerr;
static my_bpftimeval open_ts;
static my_bpftimeval close_ts;
#define COUNTS_PREFIX_DEFAULT "rssm"
static char* counts_prefix            = 0;
static char* sources_prefix           = 0;
static char* aggregated_prefix        = 0;
static int   dont_fork_on_close       = 0;
static int   sources_into_counters    = 0;
static int   aggregated_into_counters = 0;
static char* service_name             = 0;
static int   rssac002v3_yaml          = 0;

output_t rssm_output;

#define MAX_SIZE_INDEX 4096
#define MSG_SIZE_SHIFT 4
#define MAX_TBL_ADDRS 2000000
#define MAX_TBL_ADDRS2 200000
#define MAX_RCODE (1 << 12)

typedef struct {
    hashtbl*     tbl;
    iaddr        addrs[MAX_TBL_ADDRS];
    uint64_t     count[MAX_TBL_ADDRS];
    unsigned int num_addrs;
} my_hashtbl;

typedef struct {
    hashtbl*     tbl;
    iaddr        addrs[MAX_TBL_ADDRS2];
    uint64_t     count[MAX_TBL_ADDRS2];
    unsigned int num_addrs;
} my_hashtbl2;

struct {
    uint64_t    dns_udp_queries_received_ipv4;
    uint64_t    dns_udp_queries_received_ipv6;
    uint64_t    dns_tcp_queries_received_ipv4;
    uint64_t    dns_tcp_queries_received_ipv6;
    uint64_t    dns_udp_responses_sent_ipv4;
    uint64_t    dns_udp_responses_sent_ipv6;
    uint64_t    dns_tcp_responses_sent_ipv4;
    uint64_t    dns_tcp_responses_sent_ipv6;
    uint64_t    udp_query_size[MAX_SIZE_INDEX];
    uint64_t    tcp_query_size[MAX_SIZE_INDEX];
    uint64_t    udp_response_size[MAX_SIZE_INDEX];
    uint64_t    tcp_response_size[MAX_SIZE_INDEX];
    uint64_t    rcodes[MAX_RCODE];
    my_hashtbl  sources;
    my_hashtbl2 aggregated;
    uint64_t    num_ipv4_sources;
    uint64_t    num_ipv6_sources;
} counts;

static unsigned int
iaddr_hash(const void* key)
{
    const iaddr* ia = (const iaddr*)key;

    if (AF_INET == ia->af)
        return ia->u.a4.s_addr >> 8;
    else if (AF_INET6 == ia->af) {
        uint16_t* h = (uint16_t*)&ia->u;
        return h[2] + h[3] + h[4];
    } else
        return 0;
}

static int
iaddr_cmp(const void* _a, const void* _b)
{
    const iaddr *a = (const iaddr*)_a, *b = (const iaddr*)_b;

    if (a->af == b->af) {
        if (AF_INET == a->af)
            return memcmp(&a->u.a4.s_addr, &b->u.a4.s_addr, sizeof(a->u.a4.s_addr));
        if (AF_INET6 == a->af)
            return memcmp(&a->u.a6.s6_addr, &b->u.a6.s6_addr, sizeof(a->u.a6.s6_addr));
        return 0;
    }
    if (a->af < b->af)
        return -1;
    return 1;
}

ia_str_t ia_str = 0;

void rssm_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_IA_STR:
        ia_str = (ia_str_t)arg;
        break;
    }
}

void rssm_usage()
{
    fprintf(stderr,
        "\nrssm.so options:\n"
        "\t-?         print these instructions and exit\n"
        "\t-w <name>  write basic counters to <name>.<timesec>.<timeusec>\n"
        "\t-Y         use RSSAC002v3 YAML format when writing counters, the\n"
        "\t           file will contain multiple YAML documents, one for each\n"
        "\t           RSSAC002v3 metric\n"
        "\t           Used with; -S adds custom metric \"dnscap-rssm-sources\"\n"
        "\t           and -A adds \"dnscap-rssm-aggregated-sources\"\n"
        "\t-n <name>  the service name to use in RSSAC002v3 YAML\n"
        "\t-S         write source IPs into counters file with the prefix\n"
        "\t           \"source\" or ...\n"
        "\t-s <name>  write source IPs to <name>.<timesec>.<timeusec>\n"
        "\t-A         write aggregated IPv6(/64) sources into counters file\n"
        "\t           with the prefix \"aggregated-source\" or ...\n"
        "\t-a <name>  write aggregated IPv6(/64) sources to\n"
        "\t           <name>.<timesec>.<timeusec>\n"
        "\t-D         don't fork on close\n");
}

void rssm_getopt(int* argc, char** argv[])
{
    int c;
    while ((c = getopt(*argc, *argv, "?w:Yn:Ss:Aa:D")) != EOF) {
        switch (c) {
        case 'w':
            if (counts_prefix)
                free(counts_prefix);
            counts_prefix = strdup(optarg);
            break;
        case 'Y':
            rssac002v3_yaml = 1;
            break;
        case 'n':
            if (service_name)
                free(service_name);
            service_name = strdup(optarg);
            break;
        case 'S':
            sources_into_counters = 1;
            break;
        case 's':
            if (sources_prefix)
                free(sources_prefix);
            sources_prefix = strdup(optarg);
            break;
        case 'A':
            aggregated_into_counters = 1;
            break;
        case 'a':
            if (aggregated_prefix)
                free(aggregated_prefix);
            aggregated_prefix = strdup(optarg);
            break;
        case 'D':
            dont_fork_on_close = 1;
            break;
        case '?':
            rssm_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }
    if (sources_into_counters && sources_prefix) {
        fprintf(stderr, "rssm: -S and -s can not be used at the same time!\n");
        rssm_usage();
        exit(1);
    }
    if (aggregated_into_counters && aggregated_prefix) {
        fprintf(stderr, "rssm: -A and -a can not be used at the same time!\n");
        rssm_usage();
        exit(1);
    }
    if (rssac002v3_yaml && !service_name) {
        fprintf(stderr, "rssm: service name (-n) needed for RSSAC002v3 YAML (-Y) output!\n");
        rssm_usage();
        exit(1);
    }
}

int rssm_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void rssm_stop()
{
}

int rssm_open(my_bpftimeval ts)
{
    open_ts = ts;
    if (counts.sources.tbl)
        hash_destroy(counts.sources.tbl);
    if (counts.aggregated.tbl)
        hash_destroy(counts.aggregated.tbl);
    memset(&counts, 0, sizeof(counts));
    if (!(counts.sources.tbl = hash_create(65536, iaddr_hash, iaddr_cmp, 0))) {
        return -1;
    }
    if (!(counts.aggregated.tbl = hash_create(4096, iaddr_hash, iaddr_cmp, 0))) {
        return -1;
    }
    return 0;
}

void rssm_save_counts(const char* sbuf)
{
    FILE* fp;
    int   i;
    char* tbuf = 0;
    i          = asprintf(&tbuf, "%s.%s.%06lu", counts_prefix ? counts_prefix : COUNTS_PREFIX_DEFAULT, sbuf, (u_long)open_ts.tv_usec);
    if (i < 1 || !tbuf) {
        logerr("asprintf: out of memory");
        return;
    }
    fprintf(stderr, "rssm: saving counts in %s\n", tbuf);
    fp = fopen(tbuf, "w");
    if (!fp) {
        logerr("%s: %s", sbuf, strerror(errno));
        free(tbuf);
        return;
    }
    if (rssac002v3_yaml) {
        char      tz[21];
        struct tm tm;

        gmtime_r((time_t*)&open_ts.tv_sec, &tm);
        if (!strftime(tz, sizeof(tz), "%Y-%m-%dT%H:%M:%SZ", &tm)) {
            logerr("rssm: strftime failed");
            fclose(fp);
            free(tbuf);
            return;
        }

        fprintf(fp, "---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: traffic-volume\n", service_name, tz);
        fprintf(fp, "dns-udp-queries-received-ipv4: %" PRIu64 "\n", counts.dns_udp_queries_received_ipv4);
        fprintf(fp, "dns-udp-queries-received-ipv6: %" PRIu64 "\n", counts.dns_udp_queries_received_ipv6);
        fprintf(fp, "dns-tcp-queries-received-ipv4: %" PRIu64 "\n", counts.dns_tcp_queries_received_ipv4);
        fprintf(fp, "dns-tcp-queries-received-ipv6: %" PRIu64 "\n", counts.dns_tcp_queries_received_ipv6);
        fprintf(fp, "dns-udp-responses-sent-ipv4: %" PRIu64 "\n", counts.dns_udp_responses_sent_ipv4);
        fprintf(fp, "dns-udp-responses-sent-ipv6: %" PRIu64 "\n", counts.dns_udp_responses_sent_ipv6);
        fprintf(fp, "dns-tcp-responses-sent-ipv4: %" PRIu64 "\n", counts.dns_tcp_responses_sent_ipv4);
        fprintf(fp, "dns-tcp-responses-sent-ipv6: %" PRIu64 "\n", counts.dns_tcp_responses_sent_ipv6);

        fprintf(fp, "\n---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: traffic-sizes\n", service_name, tz);
        i = 0;
        for (; i < MAX_SIZE_INDEX; i++) {
            if (counts.udp_query_size[i]) {
                break;
            }
        }
        if (i < MAX_SIZE_INDEX) {
            fprintf(fp, "udp-request-sizes:\n");
            for (; i < MAX_SIZE_INDEX; i++) {
                if (counts.udp_query_size[i]) {
                    fprintf(fp, "  %d-%d: %" PRIu64 "\n",
                        i << MSG_SIZE_SHIFT,
                        ((i + 1) << MSG_SIZE_SHIFT) - 1,
                        counts.udp_query_size[i]);
                }
            }
        } else {
            fprintf(fp, "udp-request-sizes: {}\n");
        }
        i = 0;
        for (; i < MAX_SIZE_INDEX; i++) {
            if (counts.udp_response_size[i]) {
                break;
            }
        }
        if (i < MAX_SIZE_INDEX) {
            fprintf(fp, "udp-response-sizes:\n");
            for (; i < MAX_SIZE_INDEX; i++) {
                if (counts.udp_response_size[i]) {
                    fprintf(fp, "  %d-%d: %" PRIu64 "\n",
                        i << MSG_SIZE_SHIFT,
                        ((i + 1) << MSG_SIZE_SHIFT) - 1,
                        counts.udp_response_size[i]);
                }
            }
        } else {
            fprintf(fp, "udp-response-sizes: {}\n");
        }
        i = 0;
        for (; i < MAX_SIZE_INDEX; i++) {
            if (counts.tcp_query_size[i]) {
                break;
            }
        }
        if (i < MAX_SIZE_INDEX) {
            fprintf(fp, "tcp-request-sizes:\n");
            for (; i < MAX_SIZE_INDEX; i++) {
                if (counts.tcp_query_size[i]) {
                    fprintf(fp, "  %d-%d: %" PRIu64 "\n",
                        i << MSG_SIZE_SHIFT,
                        ((i + 1) << MSG_SIZE_SHIFT) - 1,
                        counts.tcp_query_size[i]);
                }
            }
        } else {
            fprintf(fp, "tcp-request-sizes: {}\n");
        }
        i = 0;
        for (; i < MAX_SIZE_INDEX; i++) {
            if (counts.tcp_response_size[i]) {
                break;
            }
        }
        if (i < MAX_SIZE_INDEX) {
            fprintf(fp, "tcp-response-sizes:\n");
            for (; i < MAX_SIZE_INDEX; i++) {
                if (counts.tcp_response_size[i]) {
                    fprintf(fp, "  %d-%d: %" PRIu64 "\n",
                        i << MSG_SIZE_SHIFT,
                        ((i + 1) << MSG_SIZE_SHIFT) - 1,
                        counts.tcp_response_size[i]);
                }
            }
        } else {
            fprintf(fp, "tcp-response-sizes: {}\n");
        }

        fprintf(fp, "\n---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: rcode-volume\n", service_name, tz);
        for (i = 0; i < MAX_RCODE; i++) {
            if (counts.rcodes[i]) {
                fprintf(fp, "%d: %" PRIu64 "\n", i, counts.rcodes[i]);
            }
        }

        fprintf(fp, "\n---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: unique-sources\n", service_name, tz);
        fprintf(fp, "num-sources-ipv4: %" PRIu64 "\n", counts.num_ipv4_sources);
        fprintf(fp, "num-sources-ipv6: %" PRIu64 "\n", counts.num_ipv6_sources);
        fprintf(fp, "num-sources-ipv6-aggregate: %u\n", counts.aggregated.num_addrs);

        if (sources_into_counters) {
            fprintf(fp, "\n---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: dnscap-rssm-sources\n", service_name, tz);
            if (counts.sources.num_addrs) {
                fprintf(fp, "sources:\n");
                for (i = 0; i < counts.sources.num_addrs; i++) {
                    fprintf(fp, "  %s: %" PRIu64 "\n", ia_str(counts.sources.addrs[i]), counts.sources.count[i]);
                }
            } else {
                fprintf(fp, "sources: {}\n");
            }
        }

        if (aggregated_into_counters) {
            fprintf(fp, "\n---\nversion: rssac002v3\nservice: %s\nstart-period: %s\nmetric: dnscap-rssm-aggregated-sources\n", service_name, tz);
            if (counts.aggregated.num_addrs) {
                fprintf(fp, "aggregated-sources:\n");
                for (i = 0; i < counts.aggregated.num_addrs; i++) {
                    fprintf(fp, "  %s: %" PRIu64 "\n", ia_str(counts.aggregated.addrs[i]), counts.aggregated.count[i]);
                }
            } else {
                fprintf(fp, "aggregated-sources: {}\n");
            }
        }
    } else {
        fprintf(fp, "first-packet-time %ld\n", (long)open_ts.tv_sec);
        fprintf(fp, "last-packet-time %ld\n", (long)close_ts.tv_sec);
        fprintf(fp, "dns-udp-queries-received-ipv4 %" PRIu64 "\n", counts.dns_udp_queries_received_ipv4);
        fprintf(fp, "dns-udp-queries-received-ipv6 %" PRIu64 "\n", counts.dns_udp_queries_received_ipv6);
        fprintf(fp, "dns-tcp-queries-received-ipv4 %" PRIu64 "\n", counts.dns_tcp_queries_received_ipv4);
        fprintf(fp, "dns-tcp-queries-received-ipv6 %" PRIu64 "\n", counts.dns_tcp_queries_received_ipv6);
        fprintf(fp, "dns-udp-responses-sent-ipv4 %" PRIu64 "\n", counts.dns_udp_responses_sent_ipv4);
        fprintf(fp, "dns-udp-responses-sent-ipv6 %" PRIu64 "\n", counts.dns_udp_responses_sent_ipv6);
        fprintf(fp, "dns-tcp-responses-sent-ipv4 %" PRIu64 "\n", counts.dns_tcp_responses_sent_ipv4);
        fprintf(fp, "dns-tcp-responses-sent-ipv6 %" PRIu64 "\n", counts.dns_tcp_responses_sent_ipv6);
        for (i = 0; i < MAX_SIZE_INDEX; i++)
            if (counts.udp_query_size[i])
                fprintf(fp, "dns-udp-query-size %d-%d %" PRIu64 "\n",
                    i << MSG_SIZE_SHIFT,
                    ((i + 1) << MSG_SIZE_SHIFT) - 1,
                    counts.udp_query_size[i]);
        for (i = 0; i < MAX_SIZE_INDEX; i++)
            if (counts.tcp_query_size[i])
                fprintf(fp, "dns-tcp-query-size %d-%d %" PRIu64 "\n",
                    i << MSG_SIZE_SHIFT,
                    ((i + 1) << MSG_SIZE_SHIFT) - 1,
                    counts.tcp_query_size[i]);
        for (i = 0; i < MAX_SIZE_INDEX; i++)
            if (counts.udp_response_size[i])
                fprintf(fp, "dns-udp-response-size %d-%d %" PRIu64 "\n",
                    i << MSG_SIZE_SHIFT,
                    ((i + 1) << MSG_SIZE_SHIFT) - 1,
                    counts.udp_response_size[i]);
        for (i = 0; i < MAX_SIZE_INDEX; i++)
            if (counts.tcp_response_size[i])
                fprintf(fp, "dns-tcp-response-size %d-%d %" PRIu64 "\n",
                    i << MSG_SIZE_SHIFT,
                    ((i + 1) << MSG_SIZE_SHIFT) - 1,
                    counts.tcp_response_size[i]);
        for (i = 0; i < MAX_RCODE; i++)
            if (counts.rcodes[i])
                fprintf(fp, "dns-rcode %d %" PRIu64 "\n",
                    i, counts.rcodes[i]);
        fprintf(fp, "num-sources %u\n", counts.sources.num_addrs);
        if (sources_into_counters) {
            for (i = 0; i < counts.sources.num_addrs; i++) {
                fprintf(fp, "source %s %" PRIu64 "\n", ia_str(counts.sources.addrs[i]), counts.sources.count[i]);
            }
        }
        if (aggregated_into_counters) {
            for (i = 0; i < counts.aggregated.num_addrs; i++) {
                fprintf(fp, "aggregated-source %s %" PRIu64 "\n", ia_str(counts.aggregated.addrs[i]), counts.aggregated.count[i]);
            }
        }
    }
    fclose(fp);
    fprintf(stderr, "rssm: done\n");
    free(tbuf);
}

void rssm_save_sources(const char* sbuf)
{
    FILE* fp;
    char* tbuf = 0;
    int   i;
    i = asprintf(&tbuf, "%s.%s.%06lu", sources_prefix, sbuf, (u_long)open_ts.tv_usec);
    if (i < 1 || !tbuf) {
        logerr("asprintf: out of memory");
        return;
    }
    fprintf(stderr, "rssm: saving %u sources in %s\n", counts.sources.num_addrs, tbuf);
    fp = fopen(tbuf, "w");
    if (!fp) {
        logerr("%s: %s", tbuf, strerror(errno));
        free(tbuf);
        return;
    }
    for (i = 0; i < counts.sources.num_addrs; i++) {
        fprintf(fp, "%s %" PRIu64 "\n", ia_str(counts.sources.addrs[i]), counts.sources.count[i]);
    }
    fclose(fp);
    fprintf(stderr, "rssm: done\n");
    free(tbuf);
}

void rssm_save_aggregated(const char* sbuf)
{
    FILE* fp;
    char* tbuf = 0;
    int   i;
    i = asprintf(&tbuf, "%s.%s.%06lu", aggregated_prefix, sbuf, (u_long)open_ts.tv_usec);
    if (i < 1 || !tbuf) {
        logerr("asprintf: out of memory");
        return;
    }
    fprintf(stderr, "rssm: saving %u aggregated in %s\n", counts.aggregated.num_addrs, tbuf);
    fp = fopen(tbuf, "w");
    if (!fp) {
        logerr("%s: %s", tbuf, strerror(errno));
        free(tbuf);
        return;
    }
    for (i = 0; i < counts.aggregated.num_addrs; i++) {
        fprintf(fp, "%s %" PRIu64 "\n", ia_str(counts.aggregated.addrs[i]), counts.aggregated.count[i]);
    }
    fclose(fp);
    fprintf(stderr, "rssm: done\n");
    free(tbuf);
}

/*
 * Fork a separate process so that we don't block the main dnscap.  Use double-fork
 * to avoid zombies for the main dnscap process.
 */
int rssm_close(my_bpftimeval ts)
{
    char      sbuf[265];
    pid_t     pid;
    struct tm tm;

    if (dont_fork_on_close) {
        struct tm tm;
        gmtime_r((time_t*)&open_ts.tv_sec, &tm);
        strftime(sbuf, sizeof(sbuf), "%Y%m%d.%H%M%S", &tm);
        close_ts = ts;
        rssm_save_counts(sbuf);
        if (sources_prefix)
            rssm_save_sources(sbuf);
        if (aggregated_prefix)
            rssm_save_aggregated(sbuf);
        return 0;
    }

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
    gmtime_r((time_t*)&open_ts.tv_sec, &tm);
    strftime(sbuf, sizeof(sbuf), "%Y%m%d.%H%M%S", &tm);
    close_ts = ts;
    rssm_save_counts(sbuf);
    if (sources_prefix)
        rssm_save_sources(sbuf);
    if (aggregated_prefix)
        rssm_save_aggregated(sbuf);
    exit(0);
}

static void
find_or_add(iaddr ia)
{
    uint64_t* c = hash_find(&ia, counts.sources.tbl);
    if (c) {
        (*c)++;
    } else {
        if (counts.sources.num_addrs == MAX_TBL_ADDRS)
            return;
        counts.sources.addrs[counts.sources.num_addrs] = ia;
        if (hash_add(&counts.sources.addrs[counts.sources.num_addrs], &counts.sources.count[counts.sources.num_addrs], counts.sources.tbl)) {
            logerr("rssm.so: unable to add address to hash");
            return;
        }
        counts.sources.count[counts.sources.num_addrs]++;
        counts.sources.num_addrs++;
        if (ia.af == AF_INET) {
            counts.num_ipv4_sources++;
        } else {
            counts.num_ipv6_sources++;
        }
    }

    if (ia.af == AF_INET6) {
        iaddr v6agg = ia;

        memset(((uint8_t*)&v6agg.u.a6) + 8, 0, 8);
        c = hash_find(&v6agg, counts.aggregated.tbl);
        if (c) {
            (*c)++;
        } else {
            if (counts.aggregated.num_addrs == MAX_TBL_ADDRS2)
                return;
            counts.aggregated.addrs[counts.aggregated.num_addrs] = v6agg;
            if (hash_add(&counts.aggregated.addrs[counts.aggregated.num_addrs], &counts.aggregated.count[counts.aggregated.num_addrs], counts.aggregated.tbl)) {
                logerr("rssm.so: unable to add aggregated address to hash");
                return;
            }
            counts.aggregated.count[counts.aggregated.num_addrs]++;
            counts.aggregated.num_addrs++;
        }
    }
}

void rssm_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    unsigned  dnslen;
    ldns_pkt* pkt = 0;

    if (!(flags & DNSCAP_OUTPUT_ISDNS))
        return;

    if (ldns_wire2pkt(&pkt, payload, payloadlen) != LDNS_STATUS_OK) {
        return;
    }

    dnslen = payloadlen >> MSG_SIZE_SHIFT;
    if (dnslen >= MAX_SIZE_INDEX)
        dnslen = MAX_SIZE_INDEX - 1;

    if (!ldns_pkt_qr(pkt)) {
        find_or_add(from);
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
        uint16_t rcode = ldns_pkt_get_rcode(pkt);
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
        if (ldns_pkt_arcount(pkt)) {
            rcode |= ((uint16_t)ldns_pkt_edns_extended_rcode(pkt) << 4);
        }
        counts.rcodes[rcode]++;
    }

    ldns_pkt_free(pkt);
}
