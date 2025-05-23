/*
 * Copyright (c) 2018-2025 OARC, Inc.
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
#include <sys/socket.h>
#include <netinet/in.h>

#include "dnscap_common.h"

#if defined(HAVE_LIBCRYPTOPANT) && defined(HAVE_CRYPTOPANT_H)
#include <cryptopANT.h>
#define USE_CRYPTOPANT 1
#include "edns0_ecs.c"
#endif

static set_iaddr_t cryptopant_set_iaddr = 0;

static logerr_t* logerr;
static int       only_clients = 0, only_servers = 0, dns_port = 53, pass4 = 0, pass6 = 0, decrypt = 0, edns = 0;

enum plugin_type cryptopant_type()
{
    return plugin_filter;
}

void usage(const char* msg)
{
    fprintf(stderr, "cryptopant.so usage error: %s\n", msg);
    exit(1);
}

void cryptopant_usage()
{
    fprintf(stderr,
        "\ncryptopant.so options:\n"
        "\t-?            print these instructions and exit\n"
        "\t-k <file>     Keyfile to use (generated by scramble_ips -G)\n"
        "\t-4 <num>      pass <num> higher bits of IPv4 through unchanged\n"
        "\t-6 <num>      pass <num> higher bits of IPv6 through unchanged\n"
        "\t-D            Decrypt IP addresses\n"
        "\t-c            Only encrypt clients (port != 53)\n"
        "\t-s            Only encrypt servers (port == 53)\n"
        "\t-p <port>     Set port for -c/-s, default 53\n"
        "\t-e            Also en/de-crypt EDNS(0) Client Subnet\n"
        "\t-E            ONLY en/de-crypt EDNS(0) Client Subnet, not IP addresses\n");
}

void cryptopant_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_SET_IADDR:
        cryptopant_set_iaddr = (set_iaddr_t)arg;
        break;
    }
}

void cryptopant_getopt(int* argc, char** argv[])
{
    int           c;
    unsigned long ul;
    char *        p, *keyfile = 0;

    while ((c = getopt(*argc, *argv, "?k:4:6:Dcsp:eE")) != EOF) {
        switch (c) {
        case 'k':
            if (keyfile) {
                free(keyfile);
            }
            keyfile = strdup(optarg);
            break;
        case '4':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > 31U)
                usage("pass IPv4 bits must be an integer 0..31");
            pass4 = (unsigned)ul;
            break;
        case '6':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > 127U)
                usage("pass IPv6 bits must be an integer 0..127");
            pass6 = (unsigned)ul;
            break;
        case 'D':
            decrypt = 1;
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
            dns_port = (unsigned)ul;
            break;
        case 'e':
            if (!edns)
                edns = 1;
            break;
        case 'E':
            edns = -1;
            break;
        case '?':
            cryptopant_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }

#ifdef USE_CRYPTOPANT
    if (!keyfile) {
        usage("must have a -k keyfile");
    }

    if (scramble_init_from_file(keyfile, SCRAMBLE_NONE, SCRAMBLE_NONE, 0)) {
        usage("unable to initialize cryptopANT");
    }
#else
    usage("no cryptopANT support built in, can't encrypt IP addresses");
#endif

    if (only_clients && only_servers) {
        usage("-c and -s options are mutually exclusive");
    }

    if (keyfile) {
        free(keyfile);
    }
}

int cryptopant_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void cryptopant_stop()
{
}

int cryptopant_open(my_bpftimeval ts)
{
    return 0;
}

int cryptopant_close(my_bpftimeval ts)
{
    return 0;
}

#ifdef USE_CRYPTOPANT
void ecs_callback(int family, u_char* buf, size_t len)
{
    switch (family) {
    case 1: // IPv4
    {
        if (len > sizeof(struct in_addr))
            break;
        struct in_addr in = { INADDR_ANY };
        memcpy(&in, buf, len);
        in.s_addr = decrypt ? unscramble_ip4(in.s_addr, pass4) : scramble_ip4(in.s_addr, pass4);
        memcpy(buf, &in, len);
        break;
    }
    case 2: // IPv6
    {
        if (len > sizeof(struct in6_addr))
            break;
        struct in6_addr in = IN6ADDR_ANY_INIT;
        memcpy(&in, buf, len);
        decrypt ? unscramble_ip6(&in, pass6) : scramble_ip6(&in, pass6);
        memcpy(buf, &in, len);
        break;
    }
    default:
        break;
    }
}
#endif

int cryptopant_filter(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    u_char* pkt_copy, const unsigned olen,
    u_char* payload, const unsigned payloadlen)
{
#ifdef USE_CRYPTOPANT
    if (edns && flags & DNSCAP_OUTPUT_ISDNS && payload && payloadlen > DNS_MSG_HDR_SZ) {
        parse_for_edns0_ecs(payload, payloadlen, ecs_callback);
        if (edns < 0)
            return 0;
    }

    for (;;) {
        if (only_clients && sport == dns_port) {
            if (sport != dport) {
                from = 0;
                break;
            }
        }
        if (only_servers && sport != dns_port) {
            from = 0;
            break;
        }

        switch (from->af) {
        case AF_INET:
            from->u.a4.s_addr = decrypt ? unscramble_ip4(from->u.a4.s_addr, pass4) : scramble_ip4(from->u.a4.s_addr, pass4);
            break;
        case AF_INET6:
            decrypt ? unscramble_ip6(&from->u.a6, pass6) : scramble_ip6(&from->u.a6, pass6);
            break;
        default:
            from = 0;
            break;
        }
        break;
    }

    for (;;) {
        if (only_clients && dport == dns_port) {
            if (dport != sport) {
                to = 0;
                break;
            }
        }
        if (only_servers && dport != dns_port) {
            to = 0;
            break;
        }

        switch (to->af) {
        case AF_INET:
            to->u.a4.s_addr = decrypt ? unscramble_ip4(to->u.a4.s_addr, pass4) : scramble_ip4(to->u.a4.s_addr, pass4);
            break;
        case AF_INET6:
            decrypt ? unscramble_ip6(&to->u.a6, pass6) : scramble_ip6(&to->u.a6, pass6);
            break;
        default:
            to = 0;
            break;
        }
        break;
    }

    if (cryptopant_set_iaddr && (from || to)) {
        cryptopant_set_iaddr(from, to);
    }
#endif
    return 0;
}
