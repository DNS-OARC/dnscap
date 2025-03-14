/*
 * Copyright (c) 2025 OARC, Inc.
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "dnscap_common.h"

enum plugin_type asudp_type()
{
    return plugin_filter;
}

void asudp_usage()
{
    fprintf(stderr,
        "\nasudp.so options:\n"
        "\t-T         skip packets that would be truncated\n"
        "\t-?         print these instructions and exit\n");
}

static int skip_truncated = 0;

void asudp_getopt(int* argc, char** argv[])
{
    int c;
    while ((c = getopt(*argc, *argv, "T?")) != EOF) {
        switch (c) {
        case 'T':
            skip_truncated = 1;
            break;
        case '?':
            asudp_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }
}

static set_output_pkt_t asudp_set_output_pkt = 0;

void asudp_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_SET_OUTPUT_PKT:
        asudp_set_output_pkt = (set_output_pkt_t)arg;
        break;
    }
}

struct _pkt {
    union {
        struct ip      iphdr;
        struct ip6_hdr ip6_hdr;
    };
    struct udphdr updhdr;
    uint8_t       payload[0xffff];
};
static uint8_t _pkt[sizeof(struct _pkt)];

int asudp_filter(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    u_char* pkt_copy, const unsigned olen,
    u_char* payload, const unsigned payloadlen)
{
    if (!asudp_set_output_pkt)
        return 0;
    if (!(flags & DNSCAP_OUTPUT_ISDNS) || !payloadlen) {
        return 1;
    }

    size_t   plen = payloadlen;
    uint8_t* pkt  = _pkt;

    switch (from->af) {
    case AF_INET: {
        if (plen > sizeof(((struct _pkt*)0)->payload) - sizeof(struct ip) - sizeof(struct udphdr)) {
            if (skip_truncated)
                return 1;
            plen = sizeof(((struct _pkt*)0)->payload) - sizeof(struct ip) - sizeof(struct udphdr);
        }

        struct ip ip = {};
        ip.ip_hl     = 5;
        ip.ip_v      = 4;
        ip.ip_len    = htons(sizeof(struct ip) + sizeof(struct udphdr) + plen);
        ip.ip_ttl    = 255;
        ip.ip_p      = IPPROTO_UDP;
        ip.ip_src    = from->u.a4;
        ip.ip_dst    = to->u.a4;
        memcpy(pkt, &ip, sizeof(struct ip));
        pkt += sizeof(struct ip);
        break;
    }
    case AF_INET6: {
        if (plen > sizeof(((struct _pkt*)0)->payload) - sizeof(struct ip6_hdr) - sizeof(struct udphdr)) {
            if (skip_truncated)
                return 1;
            plen = sizeof(((struct _pkt*)0)->payload) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
        }

        struct ip6_hdr ip6 = {};
        ip6.ip6_vfc        = 0x60;
        ip6.ip6_plen       = htons(sizeof(struct udphdr) + plen);
        ip6.ip6_nxt        = IPPROTO_UDP;
        ip6.ip6_src        = from->u.a6;
        ip6.ip6_dst        = to->u.a6;
        memcpy(pkt, &ip6, sizeof(struct ip6_hdr));
        pkt += sizeof(struct ip6_hdr);
        break;
    }
    default:
        return 1;
    }

    struct udphdr udp = {};
    udp.uh_sport      = htons(sport);
    udp.uh_dport      = htons(dport);
    udp.uh_ulen       = htons(sizeof(struct udphdr) + plen);
    memcpy(pkt, &udp, sizeof(struct udphdr));
    pkt += sizeof(struct udphdr);

    memcpy(pkt, payload, plen);
    pkt += plen;

    asudp_set_output_pkt(_pkt, pkt - _pkt);

    return 0;
}
