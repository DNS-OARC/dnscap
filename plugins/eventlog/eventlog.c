/* eventlog.c
 *
 * Byron Darrah - May 20, 2020
 * Version 1.0
 *
 * This is a plugin for dnscap, based on the txtout plugin.
 *
 * This plugin generates one line of output for each packet, with a human-
 * readable timestamp, and includes the results of A and AAAA queries (which
 * is either a list of IP addresses, or an NXDOMAIN flag).
 *
 * Below is the original copyright notice from txtout.c.
 */
/*
 * Copyright (c) 2016-2020, OARC, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ldns/ldns.h>

#include "dnscap_common.h"

static logerr_t* logerr;
static char*     opt_o = NULL;
static int       opt_s = 0;
static FILE*     out   = 0;
static int       opt_t = 0;
static char*     opt_n = NULL;

output_t eventlog_output;

void eventlog_usage()
{
    fprintf(stderr,
        "\neventlog.so options:\n"
        "   -?         print these instructions and exit\n"
        "   -o <arg>   output file name\n"
        "   -s         short output, only QTYPE/QNAME for IN\n"
        "   -t         prefix event messages with DNS packet timestamp\n"
        "   -n <arg>   include name with each event message\n\n"
        "Produces a line of text per packet suitable for event logging,\n"
        "including IP addresses from query responses.\n");
}

void eventlog_getopt(int* argc, char** argv[])
{
    /*
     * The "getopt" function will be called from the parent to
     * process plugin options.
     */
    int c;
    while ((c = getopt(*argc, *argv, "?so:tn:")) != EOF) {
        switch (c) {
        case 'o':
            if (opt_o)
                free(opt_o);
            opt_o = strdup(optarg);
            break;
        case 's':
            opt_s = 1;
            break;
        case 't':
            opt_t = 1;
            break;
        case 'n':
            opt_n = strdup(optarg);
            break;
        case '?':
            eventlog_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }
}

int eventlog_start(logerr_t* a_logerr)
{
    /*
     * The "start" function is called once, when the program
     * starts.  It is used to initialize the plugin.  If the
     * plugin wants to write debugging and or error messages,
     * it should save the a_logerr pointer passed from the
     * parent code.
     */
    logerr = a_logerr;
    if (opt_o) {
        out = fopen(opt_o, "a");
        if (0 == out) {
            logerr("%s: %s\n", opt_o, strerror(errno));
            exit(1);
        }
    } else {
        out = stdout;
    }
    setbuf(out, 0);

    if (opt_t) {
        time_t    curtime;
        char      time_text[25];
        struct tm res;
        curtime = time(NULL);
        if (strftime(time_text, 25, "%G %m/%d %T", localtime_r(&curtime, &res)) > 0) {
            fprintf(out, "%s ", time_text);
        } else {
            fprintf(out, "**ERROR reading time** ");
        }
    }
    if (opt_n) {
        fprintf(out, "%s ", opt_n);
    }
    fprintf(out, "DNS event logging started.\n");

    return 0;
}

void eventlog_stop()
{
    /*
     * The "start" function is called once, when the program
     * is exiting normally.  It might be used to clean up state,
     * free memory, etc.
     */
    if (out != stdout)
        fclose(out);
}

int eventlog_open(my_bpftimeval ts)
{
    /*
     * The "open" function is called at the start of each
     * collection interval, which might be based on a period
     * of time or a number of packets.  In the original code,
     * this is where we opened an output pcap file.
     */
    return 0;
}

int eventlog_close(my_bpftimeval ts)
{
    /*
     * The "close" function is called at the end of each
     * collection interval, which might be based on a period
     * of time or on a number of packets.  In the original code
     * this is where we closed an output pcap file.
     */
    return 0;
}

ia_str_t           ia_str           = 0;
tcpstate_getcurr_t tcpstate_getcurr = 0;
tcpstate_reset_t   tcpstate_reset   = 0;

void eventlog_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_IA_STR:
        ia_str = (ia_str_t)arg;
        break;
    case DNSCAP_EXT_TCPSTATE_GETCURR:
        tcpstate_getcurr = (tcpstate_getcurr_t)arg;
        break;
    case DNSCAP_EXT_TCPSTATE_RESET:
        tcpstate_reset = (tcpstate_reset_t)arg;
        break;
    }
}

static void eventlog_output_ipbytes(size_t len, const uint8_t* data)
{

    /* If there are 4 bytes, print them as an IPv4 address. */
    if (len == 4) {
        fprintf(out, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
    }

    /* If there are 16 bytes, print them as an IPv6 address. */
    else if (len == 16) {
        /* If there are 16 bytes, print them as an IPv6 address. */
        fprintf(out, "%x:%x:%x:%x:%x:%x:%x:%x",
            ((unsigned int)data[0]) << 8 | data[1],
            ((unsigned int)data[2]) << 8 | data[3],
            ((unsigned int)data[4]) << 8 | data[5],
            ((unsigned int)data[6]) << 8 | data[7],
            ((unsigned int)data[8]) << 8 | data[9],
            ((unsigned int)data[10]) << 8 | data[11],
            ((unsigned int)data[12]) << 8 | data[13],
            ((unsigned int)data[14]) << 8 | data[15]);
    }
}

void eventlog_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, unsigned olen,
    const u_char* payload, unsigned payloadlen)
{

    /* Do not output anything if there is no DNS info to report. */
    if (!(flags & DNSCAP_OUTPUT_ISDNS)) {
        return;
    }
    ldns_pkt* pkt;
    if (ldns_wire2pkt(&pkt, payload, payloadlen) != LDNS_STATUS_OK) {
        if (tcpstate_getcurr && tcpstate_reset)
            tcpstate_reset(tcpstate_getcurr(), "");
        return;
    }
    ldns_buffer* buf = ldns_buffer_new(512);
    if (!buf) {
        logerr("out of memmory\n");
        exit(1);
    }

    /*
     * Output the packet timestamp
     */
    if (opt_t) {
        char      time_text[25];
        struct tm res;
        if (strftime(time_text, 25, "%G %m/%d %T", localtime_r(&ts.tv_sec, &res)) > 0) {
            fprintf(out, "%s ", time_text);
        } else {
            fprintf(out, "**ERROR reading packet time** ");
        }
    }
    if (opt_n) {
        fprintf(out, "%s ", opt_n);
    }

    /*
     * Short output, only print QTYPE and QNAME for IN records
     */
    if (opt_s) {
        ldns_rr_list* qds = ldns_pkt_question(pkt);
        if (qds) {
            ldns_rr* qd = ldns_rr_list_rr(qds, 0);

            if (qd && ldns_rr_get_class(qd) == LDNS_RR_CLASS_IN) {
                if (ldns_rr_type2buffer_str(buf, ldns_rr_get_type(qd)) == LDNS_STATUS_OK) {
                    fprintf(out, "%s", (char*)ldns_buffer_begin(buf));
                } else {
                    fprintf(out, "ERR");
                }

                ldns_buffer_clear(buf);
                if (ldns_rdf2buffer_str(buf, ldns_rr_owner(qd)) == LDNS_STATUS_OK) {
                    fprintf(out, " %s\n", (char*)ldns_buffer_begin(buf));
                } else {
                    fprintf(out, "ERR\n");
                }
            }
        }
        ldns_pkt_free(pkt);
        ldns_buffer_free(buf);
        return;
    }

    /*
     * IP Stuff
     */
    fprintf(out, "src=%s spt=%u ", ia_str(from), sport);
    fprintf(out, "dst=%s dpt=%u ", ia_str(to), dport);
    switch (proto) {
    case 17:
        fprintf(out, "proto=UDP");
        break;
    case 6:
        fprintf(out, "proto=TCP");
        break;
    default:
        fprintf(out, "proto=%hhu", proto);
        break;
    }

    /*
     * DNS Header
     */
    fprintf(out, " mid=%u", ldns_pkt_id(pkt));
    fprintf(out, " op=%u", ldns_pkt_get_opcode(pkt));
    fprintf(out, " fl=|");
    if (ldns_pkt_qr(pkt))
        fprintf(out, "QR|");
    if (ldns_pkt_aa(pkt))
        fprintf(out, "AA|");
    if (ldns_pkt_tc(pkt))
        fprintf(out, "TC|");
    if (ldns_pkt_rd(pkt))
        fprintf(out, "RD|");
    if (ldns_pkt_ra(pkt))
        fprintf(out, "RA|");
    if (ldns_pkt_ad(pkt))
        fprintf(out, "AD|");
    if (ldns_pkt_cd(pkt))
        fprintf(out, "CD|");
    switch (ldns_pkt_get_rcode(pkt)) {
    case LDNS_RCODE_NOERROR:
        fprintf(out, " rc=OK");
        break;
    case LDNS_RCODE_NXDOMAIN:
        fprintf(out, " rc=NXDOMAIN");
        break;
    case LDNS_RCODE_SERVFAIL:
        fprintf(out, " rc=SRVFAIL");
        break;
    default:
        fprintf(out, " rc=%u", ldns_pkt_get_rcode(pkt));
        break;
    }

    ldns_rr_list* qds = ldns_pkt_question(pkt);
    ldns_rr*      qd;
    if (qds && (qd = ldns_rr_list_rr(qds, 0))) {
        if (ldns_rr_class2buffer_str(buf, ldns_rr_get_class(qd)) == LDNS_STATUS_OK) {
            fprintf(out, " cl=%s", (char*)ldns_buffer_begin(buf));
        } else {
            fprintf(out, " **ERROR parsing response record**\n");
            ldns_pkt_free(pkt);
            ldns_buffer_free(buf);
            return;
        }

        ldns_buffer_clear(buf);
        if (ldns_rr_type2buffer_str(buf, ldns_rr_get_type(qd)) == LDNS_STATUS_OK) {
            fprintf(out, " tp=%s", (char*)ldns_buffer_begin(buf));
        } else {
            fprintf(out, " **ERROR parsing response record**\n");
            ldns_pkt_free(pkt);
            ldns_buffer_free(buf);
            return;
        }

        ldns_buffer_clear(buf);
        if (ldns_rdf2buffer_str(buf, ldns_rr_owner(qd)) == LDNS_STATUS_OK) {
            fprintf(out, " name=%s\n", (char*)ldns_buffer_begin(buf));
        } else {
            fprintf(out, " **ERROR parsing response record**\n");
            ldns_pkt_free(pkt);
            ldns_buffer_free(buf);
            return;
        }
    }

    /* output the query answers */
    ldns_rr_list* ans = ldns_pkt_answer(pkt);
    if (ans) {
        const char* delim = " ans=";
        size_t      i, n;
        for (i = 0, n = ldns_rr_list_rr_count(ans); i < n; i++) {
            ldns_rr* rr = ldns_rr_list_rr(ans, i);

            if (rr) {
                switch (ldns_rr_get_type(rr)) {
                case LDNS_RR_TYPE_A:
                case LDNS_RR_TYPE_AAAA: {
                    ldns_rdf* rdf = ldns_rr_rdf(rr, 0);
                    if (rdf) {
                        fprintf(out, "%s", delim);
                        delim = ",";
                        eventlog_output_ipbytes(ldns_rdf_size(rdf), ldns_rdf_data(rdf));
                        continue;
                    }
                    break;
                }
                default:
                    continue;
                }
            }

            fprintf(out, " **ERROR parsing response record**\n");
            ldns_pkt_free(pkt);
            ldns_buffer_free(buf);
            return;
        }
    }

    /*
     * Done
     */
    fprintf(out, "\n");
    ldns_pkt_free(pkt);
    ldns_buffer_free(buf);
}
