/*
 * Copyright (c) 2016-2018, OARC, Inc.
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
#include <resolv.h>

#include "dnscap_common.h"

static logerr_t* logerr;
static char*     opt_o = 0;
static int       opt_s = 0;
static FILE*     out   = 0;

output_t txtout_output;

void txtout_usage()
{
    fprintf(stderr,
        "\ntxtout.so options:\n"
        "\t-o <arg>   output file name\n"
        "\t-s         short output, only QTYPE/QNAME for IN\n");
}

void txtout_getopt(int* argc, char** argv[])
{
    /*
     * The "getopt" function will be called from the parent to
     * process plugin options.
     */
    int c;
    while ((c = getopt(*argc, *argv, "so:")) != EOF) {
        switch (c) {
        case 'o':
            if (opt_o)
                free(opt_o);
            opt_o = strdup(optarg);
            break;
        case 's':
            opt_s = 1;
            break;
        default:
            txtout_usage();
            exit(1);
        }
    }
}

int txtout_start(logerr_t* a_logerr)
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
        out = fopen(opt_o, "w");
        if (0 == out) {
            logerr("%s: %s\n", opt_o, strerror(errno));
            exit(1);
        }
    } else {
        out = stdout;
    }
    return 0;
}

void txtout_stop()
{
    /*
     * The "start" function is called once, when the program
     * is exiting normally.  It might be used to clean up state,
     * free memory, etc.
     */
    fclose(out);
}

int txtout_open(my_bpftimeval ts)
{
    /*
     * The "open" function is called at the start of each
     * collection interval, which might be based on a period
     * of time or a number of packets.  In the original code,
     * this is where we opened an output pcap file.
     */
    return 0;
}

int txtout_close(my_bpftimeval ts)
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

void txtout_extension(int ext, void* arg)
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

void txtout_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, unsigned olen,
    const u_char* payload, unsigned payloadlen)
{
    /*
     * Short output, only print QTYPE and QNAME for IN records
     */
    if (opt_s) {
        if (flags & DNSCAP_OUTPUT_ISDNS) {
            ns_msg msg;
            int    qdcount, err = 0;
            ns_rr  rr;
            if (ns_initparse(payload, payloadlen, &msg) < 0) {
                if (tcpstate_getcurr && tcpstate_reset)
                    tcpstate_reset(tcpstate_getcurr(), "");
                return;
            }
            qdcount = ns_msg_count(msg, ns_s_qd);

            if (qdcount > 0 && 0 == (err = ns_parserr(&msg, ns_s_qd, 0, &rr)) && ns_rr_class(rr) == 1) {
                fprintf(out, "%s %s\n",
                    p_type(ns_rr_type(rr)),
                    ns_rr_name(rr));
            }
            if (err < 0) {
                if (tcpstate_getcurr && tcpstate_reset)
                    tcpstate_reset(tcpstate_getcurr(), "");
            }
        }
        return;
    }

    /*
     * IP Stuff
     */
    fprintf(out, "%10ld.%06ld", (long)ts.tv_sec, (long)ts.tv_usec);
    fprintf(out, " %s %u", ia_str(from), sport);
    fprintf(out, " %s %u", ia_str(to), dport);
    fprintf(out, " %hhu", proto);

    if (flags & DNSCAP_OUTPUT_ISDNS) {
        ns_msg msg;
        int    qdcount, err = 0;
        ns_rr  rr;
        if (ns_initparse(payload, payloadlen, &msg) < 0) {
            if (tcpstate_getcurr && tcpstate_reset)
                tcpstate_reset(tcpstate_getcurr(), "");
            fprintf(out, "\n");
            return;
        }

        /*
         * DNS Header
         */
        fprintf(out, " %u", ns_msg_id(msg));
        fprintf(out, " %u", ns_msg_getflag(msg, ns_f_opcode));
        fprintf(out, " %u", ns_msg_getflag(msg, ns_f_rcode));
        fprintf(out, " |");
        if (ns_msg_getflag(msg, ns_f_qr))
            fprintf(out, "QR|");
        if (ns_msg_getflag(msg, ns_f_aa))
            fprintf(out, "AA|");
        if (ns_msg_getflag(msg, ns_f_tc))
            fprintf(out, "TC|");
        if (ns_msg_getflag(msg, ns_f_rd))
            fprintf(out, "RD|");
        if (ns_msg_getflag(msg, ns_f_ra))
            fprintf(out, "RA|");
        if (ns_msg_getflag(msg, ns_f_ad))
            fprintf(out, "AD|");
        if (ns_msg_getflag(msg, ns_f_cd))
            fprintf(out, "CD|");

        qdcount = ns_msg_count(msg, ns_s_qd);
        if (qdcount > 0 && 0 == (err = ns_parserr(&msg, ns_s_qd, 0, &rr))) {
            fprintf(out, " %s %s %s",
                p_class(ns_rr_class(rr)),
                p_type(ns_rr_type(rr)),
                ns_rr_name(rr));
        }
        if (err < 0) {
            if (tcpstate_getcurr && tcpstate_reset)
                tcpstate_reset(tcpstate_getcurr(), "");
        }
    }
    /*
     * Done
     */
    fprintf(out, "\n");
}
