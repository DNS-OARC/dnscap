/*
 * Copyright (c) 2016-2025 OARC, Inc.
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

#ifndef __dnscap_dnscap_common_h
#define __dnscap_dnscap_common_h

#include <netinet/in.h>
#include <sys/types.h>
#include <time.h>

/* Macros for printing timeval */
#include <inttypes.h>
#if _TIME_BITS == 64
#define PRI_tv_sec PRId64
#define PRI_tv_usec PRId64
#else
#ifdef __OpenBSD__
#define PRI_tv_sec PRId64
#define PRI_tv_usec "ld"
#else
#define PRI_tv_sec "ld"
#define PRI_tv_usec "ld"
#endif
#endif

/*
 * setup MY_BPFTIMEVAL as the timeval structure that bpf packets
 * will be assoicated with packets from libpcap
 */
#ifndef MY_BPFTIMEVAL
#define MY_BPFTIMEVAL timeval
#endif
typedef struct MY_BPFTIMEVAL my_bpftimeval;

/*
 * Structure to contain IP addresses
 */
typedef struct {
    int af;
    union {
        struct in_addr  a4;
        struct in6_addr a6;
    } u;
} iaddr;

/*
 * Prototype for the plugin "type" function
 *
 * output - Will run plugin's "output" function last when outputting (default
 *          and same behavior before the existens of a plugin type)
 * filter - Will run plugin's "filter" function before outputting and won't
 *          output if the return of that function is non-zero.
 */
enum plugin_type {
    plugin_output,
    plugin_filter,
};
typedef enum plugin_type type_t(void);

/*
 * plugins can call the logerr() function in the main dnscap
 * process.
 */
typedef int logerr_t(const char* fmt, ...);

/*
 * Prototype for the plugin "output" function
 */
typedef void output_t(const char* descr,
    iaddr                         from,
    iaddr                         to,
    uint8_t                       proto,
    unsigned                      flags,
    unsigned                      sport,
    unsigned                      dport,
    my_bpftimeval                 ts,
    const u_char*                 pkt_copy,
    const unsigned                olen,
    const u_char*                 payload,
    const unsigned                payloadlen);

/*
 * Prototype for the plugin "filter" function
 */
typedef int filter_t(const char* descr,
    iaddr*                       from,
    iaddr*                       to,
    uint8_t                      proto,
    unsigned                     flags,
    unsigned                     sport,
    unsigned                     dport,
    my_bpftimeval                ts,
    u_char*                      pkt_copy,
    unsigned                     olen,
    u_char*                      payload,
    unsigned                     payloadlen);

/*
 * Extensions
 */

#define DNSCAP_EXT_IS_RESPONDER 1
typedef int (*is_responder_t)(iaddr ia);

#define DNSCAP_EXT_IA_STR 2
typedef const char* (*ia_str_t)(iaddr ia);

#define DNSCAP_EXT_TCPSTATE_GETCURR 3
typedef void* (*tcpstate_getcurr_t)(void);

#define DNSCAP_EXT_TCPSTATE_RESET 4
typedef void (*tcpstate_reset_t)(void* tcpstate, const char* msg);

#define DNSCAP_EXT_SET_IADDR 5
typedef void (*set_iaddr_t)(iaddr* from, iaddr* to);

#define DNSCAP_EXT_SET_OUTPUT_PKT 6
typedef void (*set_output_pkt_t)(u_char* pkt, const unsigned olen);

#define DNSCAP_EXT_GET_PCAP_THREAD_FTELL 7
typedef long (*get_pcap_thread_ftell_t)(void);

#define DNSCAP_EXT_GET_PKTHDR_CAPLEN 8
typedef size_t (*get_pkthdr_caplen_t)(void);

/*
 * Flags
 */

#define DNSCAP_OUTPUT_ISFRAG (1 << 0)
#define DNSCAP_OUTPUT_ISDNS (1 << 1)
#define DNSCAP_OUTPUT_ISLAYER (1 << 2)

/*
 * Direction
 */

#define DIR_INITIATE 0x0001
#define DIR_RESPONSE 0x0002

#endif /* __dnscap_dnscap_common_h */
