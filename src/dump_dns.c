/* dump_dns.c - library function to emit decoded dns message on a FILE.
 *
 * By: Paul Vixie, ISC, October 2007
 */

/*
 * Copyright (c) 2016-2023, OARC, Inc.
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

#include "dnscap_common.h"

#include "dump_dns.h"
#include "network.h"
#include "tcpstate.h"
#include "endian_compat.h"

#include <ldns/ldns.h>
#include <netinet/in.h>

static inline uint16_t _need16(const void* ptr)
{
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return be16toh(v);
}

static void dump_dns_rr(ldns_rr* rr, FILE* trace, ldns_buffer* lbuf, bool qsect)
{
    size_t    rdlen, i;
    ldns_rdf* rdf;

    // owner
    ldns_buffer_clear(lbuf);
    if (ldns_rdf2buffer_str(lbuf, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
        goto error;
    }
    fprintf(trace, "%s", (char*)ldns_buffer_begin(lbuf));

    // class
    ldns_buffer_clear(lbuf);
    if (ldns_rr_class2buffer_str(lbuf, ldns_rr_get_class(rr)) != LDNS_STATUS_OK) {
        goto error;
    }
    fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));

    // type
    ldns_buffer_clear(lbuf);
    if (ldns_rr_type2buffer_str(lbuf, ldns_rr_get_type(rr)) != LDNS_STATUS_OK) {
        goto error;
    }
    fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));

    if (qsect)
        return;

    fprintf(trace, ",%u", ldns_rr_ttl(rr));
    switch (ldns_rr_get_type(rr)) {
    case LDNS_RR_TYPE_SOA:
        for (i = 0; i < 2; i++) {
            if (!(rdf = ldns_rr_rdf(rr, i))) {
                goto error;
            }
            ldns_buffer_clear(lbuf);
            if (ldns_rdf2buffer_str(lbuf, rdf) != LDNS_STATUS_OK) {
                goto error;
            }
            fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));
        }
        for (; i < 7; i++) {
            if (!(rdf = ldns_rr_rdf(rr, i))) {
                goto error;
            }
            ldns_buffer_clear(lbuf);
            if (ldns_rdf2buffer_str(lbuf, rdf) != LDNS_STATUS_OK) {
                goto error;
            }
            fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));
        }
        break;

    case LDNS_RR_TYPE_A:
    case LDNS_RR_TYPE_AAAA:
    case LDNS_RR_TYPE_MX:
        if (!(rdf = ldns_rr_rdf(rr, 0))) {
            goto error;
        }
        ldns_buffer_clear(lbuf);
        if (ldns_rdf2buffer_str(lbuf, rdf) != LDNS_STATUS_OK) {
            goto error;
        }
        fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));
        break;

    case LDNS_RR_TYPE_NS:
    case LDNS_RR_TYPE_PTR:
    case LDNS_RR_TYPE_CNAME:
        if (!(rdf = ldns_rr_rdf(rr, 0))) {
            goto error;
        }
        ldns_buffer_clear(lbuf);
        if (ldns_rdf2buffer_str(lbuf, rdf) != LDNS_STATUS_OK) {
            goto error;
        }
        fprintf(trace, ",%s", (char*)ldns_buffer_begin(lbuf));
        break;

    default:
        goto error;
    }
    return;

error:
    for (rdlen = 0, i = 0, rdf = ldns_rr_rdf(rr, i); rdf; rdf = ldns_rr_rdf(rr, ++i)) {
        rdlen += ldns_rdf_size(rdf);
    }
    fprintf(trace, ",[%zu]", rdlen);
}

static void dump_dns_sect(ldns_rr_list* rrs, FILE* trace, const char* endline, ldns_buffer* lbuf, bool qsect, bool ansect, ldns_pkt* pkt)
{
    size_t      rrnum, rrmax;
    const char* sep;

    if (ansect && ldns_pkt_edns(pkt)) {
        rrmax = ldns_rr_list_rr_count(rrs);
        fprintf(trace, " %s%zu", endline, rrmax + 1);
        sep = "";
        for (rrnum = 0; rrnum < rrmax; rrnum++) {
            fprintf(trace, " %s", sep);
            dump_dns_rr(ldns_rr_list_rr(rrs, rrnum), trace, lbuf, qsect);
            sep = endline;
        }
        ldns_rdf* edns_data = ldns_pkt_edns_data(pkt);
        fprintf(trace, " %s.,%u,%u,0,edns0[len=%zu,UDP=%u,ver=%u,rcode=%u,DO=%u,z=%u]",
            sep, ldns_pkt_edns_udp_size(pkt), ldns_pkt_edns_udp_size(pkt),
            edns_data ? ldns_rdf_size(edns_data) : 0,
            ldns_pkt_edns_udp_size(pkt),
            ldns_pkt_edns_version(pkt),
            ldns_pkt_edns_extended_rcode(pkt),
            ldns_pkt_edns_do(pkt) ? 1 : 0,
            ldns_pkt_edns_z(pkt));
        if (edns_data) {
            size_t   len = ldns_rdf_size(edns_data);
            uint8_t* d   = ldns_rdf_data(edns_data);

            while (len >= 4) {
                uint16_t opcode = _need16(d);
                uint16_t oplen  = _need16(d + 2);
                len -= 4;
                d += 4;

                if (oplen > len) {
                    break;
                }
                switch (opcode) {
                case 8: {
                    if (oplen >= 4) {
                        uint16_t        family            = _need16(d);
                        uint8_t         source_prefix_len = *(d + 2), scope_prefix_len = *(d + 3);
                        char            addr[(INET_ADDRSTRLEN < INET6_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN) + 1] = { 0 };
                        struct in_addr  in4                                                                                 = { .s_addr = INADDR_ANY };
                        struct in6_addr in6                                                                                 = IN6ADDR_ANY_INIT;
                        void*           in                                                                                  = 0;
                        int             af;

                        switch (family) {
                        case 1: {
                            memcpy(&in4.s_addr, d + 4, oplen - 4 > sizeof(in4.s_addr) ? sizeof(in4.s_addr) : oplen - 4);
                            in = &in4;
                            af = AF_INET;
                            break;
                        }
                        case 2: {
                            memcpy(&in6.s6_addr, d + 4, oplen - 4 > sizeof(in6.s6_addr) ? sizeof(in6.s6_addr) : oplen - 4);
                            in = &in6;
                            af = AF_INET6;
                            break;
                        }
                        default:
                            break;
                        }

                        fprintf(trace, ",edns0opt[ECS,family=%u,source=%u,scope=%u,", family, source_prefix_len, scope_prefix_len);

                        if (!in || !inet_ntop(af, in, addr, sizeof(addr) - 1)) {
                            fprintf(trace, "addr=INVALID]");
                        } else {
                            fprintf(trace, "addr=%s]", addr);
                        }

                        break;
                    }
                }

                default:
                    fprintf(trace, ",edns0opt[code=%u,codelen=%u]", opcode, oplen);
                    break;
                }

                len -= oplen;
                d += oplen;
            }
        }
        return;
    }

    rrmax = ldns_rr_list_rr_count(rrs);
    if (rrmax == 0) {
        fputs(" 0", trace);
        return;
    }
    fprintf(trace, " %s%zu", endline, rrmax);
    sep = "";
    for (rrnum = 0; rrnum < rrmax; rrnum++) {
        fprintf(trace, " %s", sep);
        dump_dns_rr(ldns_rr_list_rr(rrs, rrnum), trace, lbuf, qsect);
        sep = endline;
    }
}

void dump_dns(const u_char* payload, size_t paylen, FILE* trace, const char* endline)
{
    const char*  sep;
    tcpstate_ptr tcpstate;
    ldns_pkt*    pkt  = 0;
    ldns_buffer* lbuf = 0;
    ldns_status  ret;

    fprintf(trace, " %sdns ", endline);
    if ((ret = ldns_wire2pkt(&pkt, payload, paylen)) != LDNS_STATUS_OK) {
        /* DNS message may have padding, try get actual size */
        size_t dnslen = calcdnslen(payload, paylen);
        if (dnslen > 0 && dnslen < paylen) {
            if ((ret = ldns_wire2pkt(&pkt, payload, dnslen)) != LDNS_STATUS_OK) {
                fputs(ldns_get_errorstr_by_id(ret), trace);
                if ((tcpstate = tcpstate_getcurr()))
                    tcpstate_reset(tcpstate, strerror(errno));
                return;
            }
        } else {
            fputs(ldns_get_errorstr_by_id(ret), trace);
            if ((tcpstate = tcpstate_getcurr()))
                tcpstate_reset(tcpstate, strerror(errno));
            return;
        }
    }

    if (!(lbuf = ldns_buffer_new(512))) {
        fprintf(stderr, "%s: out of memory", ProgramName);
        exit(1);
    }

    if (ldns_pkt_opcode2buffer_str(lbuf, ldns_pkt_get_opcode(pkt)) != LDNS_STATUS_OK) {
        fprintf(stderr, "%s: unable to covert opcode to str", ProgramName);
        exit(1);
    }
    fprintf(trace, "%s,", (char*)ldns_buffer_begin(lbuf));
    ldns_buffer_clear(lbuf);
    if (ldns_pkt_rcode2buffer_str(lbuf, ldns_pkt_get_rcode(pkt)) != LDNS_STATUS_OK) {
        fprintf(stderr, "%s: unable to covert rcode to str", ProgramName);
        exit(1);
    }
    fprintf(trace, "%s,%u,", (char*)ldns_buffer_begin(lbuf), ldns_pkt_id(pkt));

    sep = "";
#define FLAG(t, f)                      \
    if (f) {                            \
        fprintf(trace, "%s%s", sep, t); \
        sep = "|";                      \
    }
    FLAG("qr", ldns_pkt_qr(pkt));
    FLAG("aa", ldns_pkt_aa(pkt));
    FLAG("tc", ldns_pkt_tc(pkt));
    FLAG("rd", ldns_pkt_rd(pkt));
    FLAG("ra", ldns_pkt_ra(pkt));
    FLAG("z", LDNS_Z_WIRE(payload));
    FLAG("ad", ldns_pkt_ad(pkt));
    FLAG("cd", ldns_pkt_cd(pkt));
#undef FLAG
    dump_dns_sect(ldns_pkt_question(pkt), trace, endline, lbuf, true, false, 0);
    dump_dns_sect(ldns_pkt_answer(pkt), trace, endline, lbuf, false, false, 0);
    dump_dns_sect(ldns_pkt_authority(pkt), trace, endline, lbuf, false, false, 0);
    dump_dns_sect(ldns_pkt_additional(pkt), trace, endline, lbuf, false, true, pkt);

    ldns_buffer_free(lbuf);
    ldns_pkt_free(pkt);
}
