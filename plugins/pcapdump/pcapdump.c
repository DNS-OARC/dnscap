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
#include <string.h>
#include <pcap.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include "dnscap_common.h"

#define SNAPLEN         65536
#define THOUSAND        1000
#define MILLION         (THOUSAND*THOUSAND)

output_t pcapdump_output;

static logerr_t *logerr = 0;
char *dump_base = 0;
static int to_stdout = 0;
static int dbg_lvl = 0;
static char *dumpname = 0;
static char *dumpnamepart = 0;
static pcap_t *pcap_dead = 0;
static pcap_dumper_t *dumper = 0;
static char *kick_cmd = 0;
static int flush = 0;
static int dir_wanted = DIR_INITIATE|DIR_RESPONSE;

void
pcapdump_usage()
{
    fprintf(stderr,
	"\npcapdump.so options:\n"
	"\t-d         increase debugging\n"
	"\t-f         flush output on every packet\n"
	"\t-k <cmd>   kick off <cmd> when each dump closes\n"
	"\t-s [ir]    select sides: initiations, responses\n"
	"\t-w <base>  dump to <base>.<timesec>.<timeusec>\n"
	);
}

void
pcapdump_getopt(int *argc, char **argv[])
{
    int c;
    int u;
    const char *p;
    while ((c = getopt(*argc, *argv, "dfk:s:w:")) != EOF) {
	switch (c) {
	case 'd':
	    dbg_lvl++;
	    break;
	case 'f':
	    flush = 1;
	    break;
	case 'k':
	    if (kick_cmd)
	        free(kick_cmd);
	    kick_cmd = strdup(optarg);
	    break;
	case 's':
	    u = 0;
	    for (p = optarg; *p; p++)
		switch (*p) {
		    case 'i': u |= DIR_INITIATE; break;
		    case 'r': u |= DIR_RESPONSE; break;
		    default: fprintf(stderr, "-s takes only [ir]\n"); pcapdump_usage(); break;
		}
	    dir_wanted = u;
	    break;
	case 'w':
	    if (!strcmp(optarg, "-"))
		to_stdout = 1;
	    else {
	        if (dump_base)
	            free(dump_base);
            dump_base = strdup(optarg);
		}
	    break;
	default:
	    pcapdump_usage();
	    exit(1);
	}
    }
    if (!to_stdout && !dump_base) {
	fprintf(stderr, "-w basename argument is required\n");
	pcapdump_usage();
	exit(1);
    }
    if (to_stdout && kick_cmd) {
	fprintf(stderr, "Can't use -k when dumping to stdout\n");
	pcapdump_usage();
	exit(1);
    }
}

int
pcapdump_start(logerr_t * a_logerr)
{
    logerr = a_logerr;
    pcap_dead = pcap_open_dead(DLT_RAW, SNAPLEN);
    return 0;
}

void
pcapdump_stop()
{
    pcap_close(pcap_dead);
    pcap_dead = 0;
}

int
pcapdump_open(my_bpftimeval ts)
{
    const char *t = NULL;
    if (to_stdout) {
	t = "-";
    } else {
	char sbuf[64];
	while (ts.tv_usec >= MILLION) {
	    ts.tv_sec++;
	    ts.tv_usec -= MILLION;
	}
	strftime(sbuf, 64, "%Y%m%d.%H%M%S", gmtime((time_t *) & ts.tv_sec));
	if (asprintf(&dumpname, "%s.%s.%06lu",
		dump_base, sbuf, (u_long) ts.tv_usec) < 0 || asprintf(&dumpnamepart, "%s.part", dumpname) < 0) {
	    logerr("asprintf: %s", strerror(errno));
	    return 1;
	}
	t = dumpnamepart;
    }
    dumper = pcap_dump_open(pcap_dead, t);
    if (dumper == NULL) {
	logerr("pcap dump open: %s", pcap_geterr(pcap_dead));
	return 1;
    }
    return 0;
}

int
pcapdump_close(my_bpftimeval ts)
{
    int ret = 0;
#if 0
    if (print_pcap_stats)
	do_pcap_stats();
#endif
    pcap_dump_close(dumper);
    dumper = 0;
    if (to_stdout) {
	assert(dumpname == 0);
	assert(dumpnamepart == 0);
	if (dbg_lvl >= 1)
	    logerr("breaking");
	ret = 0;
    } else {
	char *cmd = NULL;
	if (dbg_lvl >= 1)
	    logerr("closing %s", dumpname);
	if (rename(dumpnamepart, dumpname)) {
	    logerr("rename: %s", strerror(errno));
	    return 1;
	}
	if (kick_cmd != NULL)
	    if (asprintf(&cmd, "%s %s &", kick_cmd, dumpname) < 0) {
		logerr("asprintf: %s", strerror(errno));
		cmd = NULL;
	    }
	free(dumpnamepart);
	dumpnamepart = NULL;
	free(dumpname);
	dumpname = NULL;
	if (cmd != NULL) {
	    int x = system(cmd);
	    if (x) {
	        logerr("system %s returned %d", cmd, x);
	    }
	    free(cmd);
	}
	if (kick_cmd == NULL)
	    ret = 0;
    }
    return ret;
}

void
pcapdump_output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char * pkt_copy, const unsigned olen, const u_char * payload, const unsigned payloadlen)
{
    struct pcap_pkthdr h;
    if (flags & DNSCAP_OUTPUT_ISDNS) {
        HEADER *dns = (HEADER *) payload;
        if (0 == dns->qr && 0 == (dir_wanted&DIR_INITIATE))
	    return;
        if (1 == dns->qr && 0 == (dir_wanted&DIR_RESPONSE))
	    return;
    }
    memset(&h, 0, sizeof h);
    h.ts = ts;
    h.len = h.caplen = olen;
    pcap_dump((u_char *) dumper, &h, pkt_copy);
    if (flush)
	pcap_dump_flush(dumper);
}
