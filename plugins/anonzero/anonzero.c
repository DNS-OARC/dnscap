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

void anonzero_usage()
{
    fprintf(stderr,
        "\nanonzero.so options:\n"
        "\t-u <port>    dns port (default: 53)\n");
}

void anonzero_getopt(int* argc, char** argv[])
{
    int c;
    unsigned long ul;
    char *p;
    while ((c = getopt(*argc, *argv, "u:")) != EOF) {
        switch (c) {
        case 'u':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 1U || ul > 65535U) {
                fprintf(stderr, "port must be an integer 1..65535");
                exit(1);
            }
            port = (uint16_t)ul;
            break;
        default:
            anonzero_usage();
            exit(1);
        }
    }
}

int anonzero_start(logerr_t* a_logerr)
{
    return 0;
}

void anonzero_stop()
{
}

int anonzero_open(my_bpftimeval ts)
{
    return 0;
}

int anonzero_close(my_bpftimeval ts)
{
    return 0;
}

static void truncate_iaddr(iaddr* ip)
{
    uint8_t* p = (uint8_t*)(&ip->u);

    if (AF_INET == ip->af) {
        /* overwrite the last octet of the address */
        p[3] = 0;
    } else if (AF_INET6 == ip->af) {
        /* overwrite the last 9 octets of the address (/56) */
        memset(p + 7, 0, 9);
    }
}

void anonzero_output(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    /* assume traffic direction based on port */
    if (dport == port) {
        truncate_iaddr(from);
    }
    if (sport == port) {
        truncate_iaddr(to);
    }
}
