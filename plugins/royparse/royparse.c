/*
 * Author Roy Arends
 *
 * Copyright (c) 2017-2021, OARC, Inc.
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

#include "dnscap_common.h"

#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <pcap.h>
#include <ldns/ldns.h>

static logerr_t* logerr;
static char*     opt_q = 0;
static char*     opt_r = 0;

pcap_t*        pcap;
pcap_dumper_t* q_out = 0;
static FILE*   r_out = 0;

output_t royparse_output;
ia_str_t royparse_ia_str = 0;

void royparse_usage()
{
    fprintf(stderr,
        "\nroyparse splits a pcap into two streams: queries in pcap format and responses in ASCII format.\n"
        "\nroyparse.so options:\n"
        "\t-?         print these instructions and exit\n"
        "\t-q <arg>   query pcap stream output file name (default: no output)\n"
        "\t-r <arg>   royparse output file name (default: stdout)\n");
}

void royparse_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_IA_STR:
        royparse_ia_str = (ia_str_t)arg;
        break;
    }
}

void royparse_getopt(int* argc, char** argv[])
{
    int c;

    while ((c = getopt(*argc, *argv, "?q:r:")) != EOF) {
        switch (c) {
        case 'q':
            if (opt_q)
                free(opt_q);
            opt_q = strdup(optarg);
            break;
        case 'r':
            if (opt_r)
                free(opt_r);
            opt_r = strdup(optarg);
            break;
        case '?':
            royparse_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }
}

int royparse_start(logerr_t* a_logerr)
{
    logerr = a_logerr;

    if (opt_q) {
        pcap  = pcap_open_dead(DLT_RAW, 65535);
        q_out = pcap_dump_open(pcap, opt_q);
        if (q_out == 0) {
            logerr("%s: %s\n", opt_q, strerror(errno));
            exit(1);
        }
    }
    if (opt_r) {
        r_out = fopen(opt_r, "w");
        if (r_out == 0) {
            logerr("%s: %s\n", opt_r, strerror(errno));
            exit(1);
        }
    } else {
        r_out = stdout;
    }
    setbuf(r_out, 0);

    return 0;
}

void royparse_stop()
{
    if (q_out != 0) {
        pcap_close(pcap);
        pcap_dump_close(q_out);
    }
    if (r_out != stdout)
        fclose(r_out);
}

int royparse_open(my_bpftimeval ts)
{
    return 0;
}

int royparse_close(my_bpftimeval ts)
{
    return 0;
}

void royparse_normalize(char* str)
{
    /*
     * The "normalize" function converts upper case characters to lower case,
     * and replaces the space and comma characters with a question mark.
     */

    for (; *str; str++) {
        if (('A' <= *str) && (*str <= 'Z')) {
            *str |= 32;
        } else if ((*str == ',') || (*str == ' ')) {
            *str = '?';
        }
    }
}

void royparse_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, unsigned olen,
    const u_char* payload, unsigned payloadlen)
{
    if (flags & DNSCAP_OUTPUT_ISDNS) {
        ldns_buffer* buf = ldns_buffer_new(512);
        if (!buf) {
            logerr("out of memmory\n");
            exit(1);
        }

        ldns_pkt* pkt;
        if (ldns_wire2pkt(&pkt, payload, payloadlen) != LDNS_STATUS_OK) {
            fprintf(r_out, "ERR\n");
            ldns_buffer_free(buf);
            return;
        }
        if (ldns_pkt_qr(pkt) && sport == 53) {
            fprintf(r_out, "%cD_", ldns_pkt_rd(pkt) ? 'R' : 'N');

            switch (ldns_pkt_get_opcode(pkt)) {
            case LDNS_PACKET_QUERY:
                fprintf(r_out, "QUERY");
                break;
            case LDNS_PACKET_NOTIFY:
                fprintf(r_out, "NOTIFY");
                break;
            case LDNS_PACKET_UPDATE:
                fprintf(r_out, "UPDATE");
                break;
            default:
                fprintf(r_out, "ELSE");
            }

            fprintf(r_out, "_%u_%cA_", ldns_pkt_ancount(pkt) ? 1 : 0, ldns_pkt_aa(pkt) ? 'A' : 'N');

            switch (ldns_pkt_get_rcode(pkt)) {
            case LDNS_RCODE_NOERROR:
                fprintf(r_out, "NOERROR");
                break;
            case LDNS_RCODE_FORMERR:
                fprintf(r_out, "FORMERR");
                break;
            case LDNS_RCODE_NXDOMAIN:
                fprintf(r_out, "NXDOMAIN");
                break;
            case LDNS_RCODE_NOTIMPL:
                fprintf(r_out, "NOTIMP");
                break;
            case LDNS_RCODE_REFUSED:
                fprintf(r_out, "REFUSED");
                break;
            case LDNS_RCODE_NOTAUTH:
                fprintf(r_out, "NOTAUTH");
                break;
            default:
                fprintf(r_out, "ELSE");
            }

            fprintf(r_out, " %s,", royparse_ia_str(to));

            ldns_rr_list* qds = ldns_pkt_question(pkt);
            ldns_rr*      qd;
            if (qds && (qd = ldns_rr_list_rr(qds, 0))) {
                if (ldns_rdf2buffer_str(buf, ldns_rr_owner(qd)) == LDNS_STATUS_OK) {
                    royparse_normalize((char*)ldns_buffer_begin(buf));
                    fprintf(r_out, "%s%s,%u", (char*)ldns_buffer_begin(buf),
                        ((char*)ldns_buffer_begin(buf))[0] == '.' ? "" : ".",
                        ldns_rr_get_type(qd));
                } else {
                    fprintf(r_out, "ERR,ERR");
                }
            } else
                fprintf(r_out, ",");

            fprintf(r_out, ",%zu,%s%s%s%s", ldns_pkt_size(pkt), ldns_pkt_id(pkt) < 256 ? "-L" : "",
                ldns_pkt_tc(pkt) ? "-TC" : "",
                ldns_pkt_ad(pkt) ? "-AD" : "",
                ldns_pkt_cd(pkt) ? "-CD" : "");
            if (ldns_pkt_edns(pkt)) {
                fprintf(r_out, "-%c", ldns_pkt_edns_do(pkt) ? 'D' : 'E');
            }
            fprintf(r_out, "\n");
        } else if (opt_q != 0 && !ldns_pkt_qr(pkt) && dport == 53) {
            struct pcap_pkthdr h;
            if (flags & DNSCAP_OUTPUT_ISLAYER) {
                ldns_pkt_free(pkt);
                ldns_buffer_free(buf);
                return;
            }
            memset(&h, 0, sizeof h);
            h.ts  = ts;
            h.len = h.caplen = olen;
            pcap_dump((u_char*)q_out, &h, pkt_copy);
        }
        ldns_pkt_free(pkt);
        ldns_buffer_free(buf);
    }
}
