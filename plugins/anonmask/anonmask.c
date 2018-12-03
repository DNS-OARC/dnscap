/*
 * Copyright (c) 2018, OARC, Inc.
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
#include <sys/socket.h>

#include "dnscap_common.h"

static set_iaddr_t anonmask_set_iaddr = 0;

static logerr_t*       logerr;
static int             only_clients = 0, only_servers = 0, mask_port = 53, mask_v4 = 24, mask_v6 = 48;
static struct in_addr  in4  = { INADDR_ANY };
static struct in6_addr in6  = IN6ADDR_ANY_INIT;
static uint32_t*       in6p = (uint32_t*)&in6;

enum plugin_type anonmask_type()
{
    return plugin_filter;
}

void usage(const char* msg)
{
    fprintf(stderr, "anonmask.so usage error: %s\n", msg);
    exit(1);
}

void anonmask_usage()
{
    fprintf(stderr,
        "\nanonmask.so options:\n"
        "\t-?            print these instructions and exit\n"
        "\t-c            Only mask clients (port != 53)\n"
        "\t-s            Only mask servers (port == 53)\n"
        "\t-p <port>     Set port for -c/-s masking, default 53\n"
        "\t-4 <netmask>  The /mask for IPv4 addresses, default /24\n"
        "\t-6 <netmask>  The /mask for IPv6 addresses, default /48\n");
}

void anonmask_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_SET_IADDR:
        anonmask_set_iaddr = (set_iaddr_t)arg;
        break;
    }
}

void anonmask_getopt(int* argc, char** argv[])
{
    int           c;
    unsigned long ul;
    char*         p;

    while ((c = getopt(*argc, *argv, "?csp:4:6:")) != EOF) {
        switch (c) {
        case '?':
            anonmask_usage();
            exit(1);
            break;
        case 'c':
            only_clients = 1;
            break;
        case 's':
            only_servers = 1;
            break;
        case 'p':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 1U || ul > 65535U)
                usage("port must be an integer 1..65535");
            mask_port = (unsigned)ul;
            break;
        case '4':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > 31U)
                usage("IPv4 mask must be an integer 0..31");
            mask_v4 = (unsigned)ul;
            break;
        case '6':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > 127U)
                usage("port must be an integer 0..127");
            mask_v6 = (unsigned)ul;
            break;
        default:
            anonmask_usage();
            exit(1);
        }
    }

    if (only_clients && only_servers) {
        usage("-c and -s options are mutually exclusive");
    }

    if (mask_v4) {
        in4.s_addr = htonl(0xffffffff << (32 - mask_v4));
    }

    if (mask_v6) {
        if (mask_v6 <= 32) {
            in6p[0] = htonl(0xffffffff << (32 - mask_v6));
        } else if (mask_v6 <= 64) {
            in6p[0] = 0xffffffff;
            in6p[1] = htonl(0xffffffff << (64 - mask_v6));
        } else if (mask_v6 <= 96) {
            in6p[0] = 0xffffffff;
            in6p[1] = 0xffffffff;
            in6p[2] = htonl(0xffffffff << (96 - mask_v6));
        } else {
            in6p[0] = 0xffffffff;
            in6p[1] = 0xffffffff;
            in6p[2] = 0xffffffff;
            in6p[3] = htonl(0xffffffff << (128 - mask_v6));
        }
    }
}

int anonmask_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void anonmask_stop()
{
}

int anonmask_open(my_bpftimeval ts)
{
    return 0;
}

int anonmask_close(my_bpftimeval ts)
{
    return 0;
}

int anonmask_filter(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    uint32_t* p6;

    for (;;) {
        if (only_clients && sport == mask_port) {
            from = 0;
            break;
        }
        if (only_servers && sport != mask_port) {
            from = 0;
            break;
        }

        switch (from->af) {
        case AF_INET:
            from->u.a4.s_addr &= in4.s_addr;
            break;
        case AF_INET6:
            p6 = (uint32_t*)&from->u.a6;
            p6[0] &= in6p[0];
            p6[1] &= in6p[1];
            p6[2] &= in6p[2];
            p6[3] &= in6p[3];
            break;
        default:
            from = 0;
            break;
        }
        break;
    }

    for (;;) {
        if (only_clients && dport == mask_port) {
            to = 0;
            break;
        }
        if (only_servers && dport != mask_port) {
            to = 0;
            break;
        }

        switch (to->af) {
        case AF_INET:
            to->u.a4.s_addr &= in4.s_addr;
            break;
        case AF_INET6:
            p6 = (uint32_t*)&to->u.a6;
            p6[0] &= in6p[0];
            p6[1] &= in6p[1];
            p6[2] &= in6p[2];
            p6[3] &= in6p[3];
            break;
        default:
            to = 0;
            break;
        }
        break;
    }

    if (anonmask_set_iaddr && (from || to)) {
        anonmask_set_iaddr(from, to);
    }

    return 0;
}
