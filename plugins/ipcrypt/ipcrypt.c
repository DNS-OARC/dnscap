/*
 * Copyright (c) 2018-2020, OARC, Inc.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dnscap_common.h"

static set_iaddr_t ipcrypt_set_iaddr = 0;

static logerr_t* logerr;
static int       only_clients = 0, only_servers = 0, dns_port = 53, iterations = 1, encrypt_v6 = 0, decrypt = 0;
static uint8_t   key[16];

/*
 * ipcrypt based on Python and Go code at https://github.com/veorq/ipcrypt
 * by Jean-Philippe Aumasson jeanphilippe.aumasson@gmail.com
 */

static inline uint8_t rotl(uint8_t b, int r)
{
    return (b << r) | (b >> (8 - r));
}

static inline void permute_fwd(uint8_t* state)
{
    state[0] += state[1];
    state[2] += state[3];
    state[1] = rotl(state[1], 2) ^ state[0];
    state[3] = rotl(state[3], 5) ^ state[2];
    // state[1] ^= state[0];
    // state[3] ^= state[2];
    state[0] = rotl(state[0], 4) + state[3];
    // state[0] += state[3];
    state[2] += state[1];
    state[1] = rotl(state[1], 3) ^ state[2];
    state[3] = rotl(state[3], 7) ^ state[0];
    // state[1] ^= state[2];
    // state[3] ^= state[0];
    state[2] = rotl(state[2], 4);
}

static inline void permute_bwd(uint8_t* state)
{
    state[2] = rotl(state[2], 4);
    state[1] ^= state[2];
    state[3] ^= state[0];
    state[1] = rotl(state[1], 5);
    state[3] = rotl(state[3], 1);
    state[0] -= state[3];
    state[2] -= state[1];
    state[0] = rotl(state[0], 4);
    state[1] ^= state[0];
    state[3] ^= state[2];
    state[1] = rotl(state[1], 6);
    state[3] = rotl(state[3], 3);
    state[0] -= state[1];
    state[2] -= state[3];
}

static inline void xor4(uint8_t* x, uint8_t* y)
{
    *(uint32_t*)x ^= *(uint32_t*)y;
    // x[0] ^= y[0];
    // x[1] ^= y[1];
    // x[2] ^= y[2];
    // x[3] ^= y[3];
}

static inline void _encrypt(uint8_t* ip)
{
    int i = iterations;
    for (; i; i--) {
        xor4(ip, key);
        permute_fwd(ip);
        xor4(ip, &key[4]);
        permute_fwd(ip);
        xor4(ip, &key[8]);
        permute_fwd(ip);
        xor4(ip, &key[12]);
    }
}

static inline void _decrypt(uint8_t* ip)
{
    int i = iterations;
    for (; i; i--) {
        xor4(ip, &key[12]);
        permute_bwd(ip);
        xor4(ip, &key[8]);
        permute_bwd(ip);
        xor4(ip, &key[4]);
        permute_bwd(ip);
        xor4(ip, key);
    }
}

enum plugin_type ipcrypt_type()
{
    return plugin_filter;
}

void usage(const char* msg)
{
    fprintf(stderr, "ipcrypt.so usage error: %s\n", msg);
    exit(1);
}

void ipcrypt_usage()
{
    fprintf(stderr,
        "\nipcrypt.so options:\n"
        "\t-?            print these instructions and exit\n"
        "\t-k <key>      A 16 character long key\n"
        "\t-f <file>     Read the 16 first bytes from file and use as key\n"
        "\t-D            Decrypt IP addresses\n"
        "\t-c            Only en/de-crypt clients (port != 53)\n"
        "\t-s            Only en/de-crypt servers (port == 53)\n"
        "\t-p <port>     Set port for -c/-s, default 53\n"
        "\t-i <num>      Number of en/de-cryption iterations, default 1\n"
        "\t-6            En/de-crypt IPv6 addresses, not default or recommended\n");
}

void ipcrypt_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_SET_IADDR:
        ipcrypt_set_iaddr = (set_iaddr_t)arg;
        break;
    }
}

void ipcrypt_getopt(int* argc, char** argv[])
{
    int           c, got_key = 0;
    unsigned long ul;
    char*         p;

    while ((c = getopt(*argc, *argv, "?k:f:Dcsp:i:6")) != EOF) {
        switch (c) {
        case '?':
            ipcrypt_usage();
            exit(1);
            break;
        case 'k':
            if (strlen(optarg) != 16) {
                usage("key must be 16 characters long");
            }
            memcpy(key, optarg, 16);
            got_key = 1;
            break;
        case 'f': {
            int     fd;
            ssize_t r;
            if ((fd = open(optarg, O_RDONLY)) < 0) {
                perror("open()");
                usage("unable to open key file");
            }
            if ((r = read(fd, key, 16)) < 0) {
                perror("read()");
                usage("unable to read from key file");
            }
            if (r != 16) {
                usage("unable to read 16 bytes from key file");
            }
            close(fd);
            got_key = 1;
            break;
        }
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
        case 'i':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 1U || ul > 65535U)
                usage("iterations must be an integer 1..65535");
            iterations = (unsigned)ul;
            break;
        case '6':
            encrypt_v6 = 1;
            break;
        default:
            ipcrypt_usage();
            exit(1);
        }
    }

    if (!got_key) {
        usage("must have -k <key> or -f <file>");
    }

    if (only_clients && only_servers) {
        usage("-c and -s options are mutually exclusive");
    }
}

int ipcrypt_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void ipcrypt_stop()
{
}

int ipcrypt_open(my_bpftimeval ts)
{
    return 0;
}

int ipcrypt_close(my_bpftimeval ts)
{
    return 0;
}

int ipcrypt_filter(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    for (;;) {
        if (only_clients && sport == dns_port) {
            from = 0;
            break;
        }
        if (only_servers && sport != dns_port) {
            from = 0;
            break;
        }

        switch (from->af) {
        case AF_INET:
            decrypt ? _decrypt((uint8_t*)&from->u.a4) : _encrypt((uint8_t*)&from->u.a4);
            break;
        case AF_INET6:
            if (encrypt_v6) {
                if (decrypt) {
                    _decrypt((uint8_t*)&from->u.a6);
                    _decrypt(((uint8_t*)&from->u.a6) + 4);
                    _decrypt(((uint8_t*)&from->u.a6) + 8);
                    _decrypt(((uint8_t*)&from->u.a6) + 12);
                } else {
                    _encrypt((uint8_t*)&from->u.a6);
                    _encrypt(((uint8_t*)&from->u.a6) + 4);
                    _encrypt(((uint8_t*)&from->u.a6) + 8);
                    _encrypt(((uint8_t*)&from->u.a6) + 12);
                }
                break;
            }
        default:
            from = 0;
            break;
        }
        break;
    }

    for (;;) {
        if (only_clients && dport == dns_port) {
            to = 0;
            break;
        }
        if (only_servers && dport != dns_port) {
            to = 0;
            break;
        }

        switch (to->af) {
        case AF_INET:
            decrypt ? _decrypt((uint8_t*)&to->u.a4) : _encrypt((uint8_t*)&to->u.a4);
            break;
        case AF_INET6:
            if (encrypt_v6) {
                if (decrypt) {
                    _decrypt((uint8_t*)&to->u.a6);
                    _decrypt(((uint8_t*)&to->u.a6) + 4);
                    _decrypt(((uint8_t*)&to->u.a6) + 8);
                    _decrypt(((uint8_t*)&to->u.a6) + 12);
                } else {
                    _encrypt((uint8_t*)&to->u.a6);
                    _encrypt(((uint8_t*)&to->u.a6) + 4);
                    _encrypt(((uint8_t*)&to->u.a6) + 8);
                    _encrypt(((uint8_t*)&to->u.a6) + 12);
                }
                break;
            }
        default:
            to = 0;
            break;
        }
        break;
    }

    if (ipcrypt_set_iaddr && (from || to)) {
        ipcrypt_set_iaddr(from, to);
    }

    return 0;
}
