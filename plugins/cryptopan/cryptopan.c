/*
 * Copyright (c) 2018-2023, OARC, Inc.
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

/*
 * Crypto-PAn encryption based on submitted extension by David Stott (Lucent)
 * https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/lucent.shtml
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

#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_CONF_H) && defined(HAVE_OPENSSL_ERR_H) && defined(HAVE_OPENSSL_EVP_H)
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define USE_OPENSSL 1
#endif

static set_iaddr_t cryptopan_set_iaddr = 0;

static logerr_t*     logerr;
static int           only_clients = 0, only_servers = 0, dns_port = 53, encrypt_v6 = 0, decrypt = 0;
static unsigned char key[16];
static unsigned char iv[16];
static unsigned char pad[16];
#ifdef USE_OPENSSL
static EVP_CIPHER_CTX* ctx = 0;
#endif

enum plugin_type cryptopan_type()
{
    return plugin_filter;
}

void usage(const char* msg)
{
    fprintf(stderr, "cryptopan.so usage error: %s\n", msg);
    exit(1);
}

void cryptopan_usage()
{
    fprintf(stderr,
        "\ncryptopan.so options:\n"
        "\t-?            print these instructions and exit\n"
        "\t-k <key>      A 16 character long key\n"
        "\t-K <file>     Read the 16 first bytes from file and use as key\n"
        "\t-i <key>      A 16 character long Initialisation Vector (IV)\n"
        "\t-I <file>     Read the 16 first bytes from file and use as IV\n"
        "\t-a <key>      A 16 character long padding\n"
        "\t-A <file>     Read the 16 first bytes from file and use as padding\n"
        "\t-D            Decrypt IP addresses\n"
        "\t-c            Only en/de-crypt clients (port != 53)\n"
        "\t-s            Only en/de-crypt servers (port == 53)\n"
        "\t-p <port>     Set port for -c/-s, default 53\n"
        "\t-6            En/de-crypt IPv6 addresses, not default or recommended\n");
}

void cryptopan_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_SET_IADDR:
        cryptopan_set_iaddr = (set_iaddr_t)arg;
        break;
    }
}

void cryptopan_getopt(int* argc, char** argv[])
{
    int           c, got_key = 0, got_iv = 0, got_pad = 0;
    unsigned long ul;
    char*         p;

    while ((c = getopt(*argc, *argv, "?k:K:i:I:a:A:Dcsp:6")) != EOF) {
        switch (c) {
        case 'k':
            if (strlen(optarg) != 16) {
                usage("key must be 16 characters long");
            }
            memcpy(key, optarg, 16);
            got_key = 1;
            break;
        case 'K': {
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
        case 'i':
            if (strlen(optarg) != 16) {
                usage("IV must be 16 characters long");
            }
            memcpy(iv, optarg, 16);
            got_iv = 1;
            break;
        case 'I': {
            int     fd;
            ssize_t r;
            if ((fd = open(optarg, O_RDONLY)) < 0) {
                perror("open()");
                usage("unable to open IV file");
            }
            if ((r = read(fd, iv, 16)) < 0) {
                perror("read()");
                usage("unable to read from IV file");
            }
            if (r != 16) {
                usage("unable to read 16 bytes from IV file");
            }
            close(fd);
            got_iv = 1;
            break;
        }
        case 'a':
            if (strlen(optarg) != 16) {
                usage("padding must be 16 characters long");
            }
            memcpy(pad, optarg, 16);
            got_pad = 1;
            break;
        case 'A': {
            int     fd;
            ssize_t r;
            if ((fd = open(optarg, O_RDONLY)) < 0) {
                perror("open()");
                usage("unable to open padding file");
            }
            if ((r = read(fd, pad, 16)) < 0) {
                perror("read()");
                usage("unable to read from padding file");
            }
            if (r != 16) {
                usage("unable to read 16 bytes from padding file");
            }
            close(fd);
            got_pad = 1;
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
        case '6':
            encrypt_v6 = 1;
            break;
        case '?':
            cryptopan_usage();
            if (!optopt || optopt == '?') {
                exit(0);
            }
            // fallthrough
        default:
            exit(1);
        }
    }

    if (!got_key || !got_iv || !got_pad) {
        usage("must have key (-k/-K), IV (-i/-I) and padding (-a/-A)");
    }

#ifdef USE_OPENSSL
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        usage("unable to create openssl cipher context");
    }
    if (!EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv, 1)) {
        unsigned long e = ERR_get_error();
        fprintf(stderr, "%s:%s:%s\n", ERR_lib_error_string(e), ERR_func_error_string(e), ERR_reason_error_string(e));
        usage("unable to initialize AES128 cipher");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    {
        unsigned char outbuf[16 + EVP_MAX_BLOCK_LENGTH];
        int           outlen = 0;

        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, pad, 16)) {
            fprintf(stderr, "cryptopan.so: error encrypting padding: %s\n", ERR_reason_error_string(ERR_get_error()));
            exit(1);
        }
        if (outlen != 16) {
            fprintf(stderr, "cryptopan.so: error encrypted padding is not 16 bytes\n");
            exit(1);
        }
        memcpy(&pad, outbuf, 16);
    }
#else
    usage("no openssl support built in, can't encrypt IP addresses");
#endif

    if (only_clients && only_servers) {
        usage("-c and -s options are mutually exclusive");
    }
}

int cryptopan_start(logerr_t* a_logerr)
{
    logerr = a_logerr;
    return 0;
}

void cryptopan_stop()
{
#ifdef USE_OPENSSL
    EVP_CIPHER_CTX_free(ctx);
    ctx = 0;
#endif
}

int cryptopan_open(my_bpftimeval ts)
{
    return 0;
}

int cryptopan_close(my_bpftimeval ts)
{
    return 0;
}

#ifdef USE_OPENSSL
struct input {
    union {
        unsigned char input[16];
        uint32_t      ui32;
    } u;
};
struct output {
    union {
        unsigned char outbuf[16 + EVP_MAX_BLOCK_LENGTH];
        uint32_t      ui32;
    } u;
};
static inline void _encrypt(uint32_t* in)
{
    struct input  input;
    struct output output;
    int           outlen = 0, pos;
    uint32_t      orig, result = 0, pad4b, mask = 0;

    memcpy(input.u.input, pad, 16);
    orig = ntohl(*in);
    memcpy(&pad4b, pad, 4);

    // First pass with padding only

    input.u.ui32 = htonl(pad4b);

    if (!EVP_CipherUpdate(ctx, output.u.outbuf, &outlen, input.u.input, 16)) {
        fprintf(stderr, "cryptopan.so: error encrypting: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(1);
    }
    if (outlen != 16) {
        fprintf(stderr, "cryptopan.so: error encrypted result is not 16 bytes\n");
        exit(1);
    }

    result |= ntohl(output.u.ui32) & 0x80000000;
    mask >>= 1;
    mask |= 0x80000000;

    for (pos = 1; pos < 32; pos++) {
        input.u.ui32 = htonl(((pad4b << pos) | (pad4b >> (32 - pos))) ^ (orig & mask));

        if (!EVP_CipherUpdate(ctx, output.u.outbuf, &outlen, input.u.input, 16)) {
            fprintf(stderr, "cryptopan.so: error encrypting: %s\n", ERR_reason_error_string(ERR_get_error()));
            exit(1);
        }
        if (outlen != 16) {
            fprintf(stderr, "cryptopan.so: error encrypted result is not 16 bytes\n");
            exit(1);
        }

        result |= (ntohl(output.u.ui32) & 0x80000000) >> pos;
        mask >>= 1;
        mask |= 0x80000000;
    }

    *in = htonl(result ^ orig);
}

static inline void _decrypt(uint32_t* in)
{
    struct input  input;
    struct output output;
    int           outlen = 0, pos;
    uint32_t      orig, pad4b, mask = 0;

    memcpy(input.u.input, pad, 16);
    orig = ntohl(*in);
    memcpy(&pad4b, pad, 4);

    // First pass with padding only

    input.u.ui32 = htonl(pad4b);

    if (!EVP_CipherUpdate(ctx, output.u.outbuf, &outlen, input.u.input, 16)) {
        fprintf(stderr, "cryptopan.so: error encrypting: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(1);
    }
    if (outlen != 16) {
        fprintf(stderr, "cryptopan.so: error encrypted result is not 16 bytes\n");
        exit(1);
    }

    orig ^= ntohl(output.u.ui32) & 0x80000000;
    mask >>= 1;
    mask |= 0x80000000;

    for (pos = 1; pos < 32; pos++) {
        input.u.ui32 = htonl(((pad4b << pos) | (pad4b >> (32 - pos))) ^ (orig & mask));

        if (!EVP_CipherUpdate(ctx, output.u.outbuf, &outlen, input.u.input, 16)) {
            fprintf(stderr, "cryptopan.so: error encrypting: %s\n", ERR_reason_error_string(ERR_get_error()));
            exit(1);
        }
        if (outlen != 16) {
            fprintf(stderr, "cryptopan.so: error encrypted result is not 16 bytes\n");
            exit(1);
        }

        orig ^= (ntohl(output.u.ui32) & 0x80000000) >> pos;
        mask >>= 1;
        mask |= 0x80000000;
    }

    *in = htonl(orig);
}
#endif

int cryptopan_filter(const char* descr, iaddr* from, iaddr* to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
#ifdef USE_OPENSSL
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
            decrypt ? _decrypt((uint32_t*)&from->u.a4) : _encrypt((uint32_t*)&from->u.a4);
            break;
        case AF_INET6:
            if (encrypt_v6) {
                if (decrypt) {
                    _decrypt((uint32_t*)&from->u.a6);
                    _decrypt(((uint32_t*)&from->u.a6) + 1); // lgtm [cpp/suspicious-pointer-scaling]
                    _decrypt(((uint32_t*)&from->u.a6) + 2); // lgtm [cpp/suspicious-pointer-scaling]
                    _decrypt(((uint32_t*)&from->u.a6) + 3); // lgtm [cpp/suspicious-pointer-scaling]
                } else {
                    _encrypt((uint32_t*)&from->u.a6);
                    _encrypt(((uint32_t*)&from->u.a6) + 1); // lgtm [cpp/suspicious-pointer-scaling]
                    _encrypt(((uint32_t*)&from->u.a6) + 2); // lgtm [cpp/suspicious-pointer-scaling]
                    _encrypt(((uint32_t*)&from->u.a6) + 3); // lgtm [cpp/suspicious-pointer-scaling]
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
            decrypt ? _decrypt((uint32_t*)&to->u.a4) : _encrypt((uint32_t*)&to->u.a4);
            break;
        case AF_INET6:
            if (encrypt_v6) {
                if (decrypt) {
                    _decrypt((uint32_t*)&to->u.a6);
                    _decrypt(((uint32_t*)&to->u.a6) + 1); // lgtm [cpp/suspicious-pointer-scaling]
                    _decrypt(((uint32_t*)&to->u.a6) + 2); // lgtm [cpp/suspicious-pointer-scaling]
                    _decrypt(((uint32_t*)&to->u.a6) + 3); // lgtm [cpp/suspicious-pointer-scaling]
                } else {
                    _encrypt((uint32_t*)&to->u.a6);
                    _encrypt(((uint32_t*)&to->u.a6) + 1); // lgtm [cpp/suspicious-pointer-scaling]
                    _encrypt(((uint32_t*)&to->u.a6) + 2); // lgtm [cpp/suspicious-pointer-scaling]
                    _encrypt(((uint32_t*)&to->u.a6) + 3); // lgtm [cpp/suspicious-pointer-scaling]
                }
                break;
            }
        default:
            to = 0;
            break;
        }
        break;
    }

    if (cryptopan_set_iaddr && (from || to)) {
        cryptopan_set_iaddr(from, to);
    }
#endif
    return 0;
}
