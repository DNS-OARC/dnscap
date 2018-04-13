/*
 * Copyright (c) 2018, Internet Systems Consortium, Inc.
 *                     OARC, Inc.
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

static uint16_t port = 53;
static int mask4_bits = 24;
static int mask6_bits = 56;

static struct in_addr mask4;
static struct in6_addr mask6;

void anonzero_usage()
{
    fprintf(stderr,
        "\nanonzero.so options:\n"
        "\t-u <port>    dns port (default: 53)\n"
        "\t-4 <bits>    mask length for IPv4 (default: 24)\n"
        "\t-6 <bits>    mask length for IPv6 (default: 56)\n");
}

static void anonzero_make_mask(uint8_t* p, int bits)
{
    int i;
    for (i = 0; i < bits; ++i) {
        int offset = i / 8;
        int bit = 7 - (i % 8);
        p[offset] |= (1 << bit);
    }
}

static void anonzero_mask_ipaddr(iaddr* ip)
{
    int i;
    uint8_t* p = (uint8_t*)(&ip->u);

    if (AF_INET == ip->af) {
        uint8_t* q = (uint8_t*)&mask4;
        for (i = 0; i < sizeof(mask4); ++i) {
            p[i] &= q[i];
        }
    } else if (AF_INET6 == ip->af) {
        uint8_t* q = (uint8_t*)&mask6;
        for (i = 0; i < sizeof(mask6); ++i) {
            p[i] &= q[i];
        }
    }
}

void anonzero_getopt(int* argc, char** argv[])
{
    int c;
    unsigned long ul;
    char *p;
    while ((c = getopt(*argc, *argv, "u:4:6:")) != EOF) {
        switch (c) {
        case 'u':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 1U || ul > 65535U) {
                fprintf(stderr, "port must be an integer 1..65535\n");
                exit(1);
            }
            port = (uint16_t)ul;
            break;
        case '4':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 0U || ul > 32U) {
                fprintf(stderr, "IPv4 mask must be an integer 0..32\n");
                exit(1);
            }
            mask4_bits = (int)ul;
            break;
        case '6':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 0U || ul > 32U) {
                fprintf(stderr, "IPv6 mask must be an integer 0..128\n");
                exit(1);
            }
            mask6_bits = (int)ul;
            break;
        default:
            anonzero_usage();
            exit(1);
        }
    }

    memset(&mask4, 0, sizeof(struct in_addr));
    anonzero_make_mask((uint8_t*)&mask4, mask4_bits);

    memset(&mask6, 0, sizeof(struct in6_addr));
    anonzero_make_mask((uint8_t*)&mask6, mask6_bits);
}

void anonzero_output(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    /* assume traffic direction based on port */
    if (dport == port) {
        anonzero_mask_ipaddr(from);
    } else if (sport == port) {
        anonzero_mask_ipaddr(to);
    }
}
