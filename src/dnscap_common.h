/*
 * Copyright (c) 2016-2018, OARC, Inc.
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

#include <netinet/in.h>
#include <sys/types.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifndef __dnscap_dnscap_common_h
#define __dnscap_dnscap_common_h

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

#define DNSCAP_EXT_IS_RESPONDER 1
typedef int (*is_responder_t)(iaddr ia);

#define DNSCAP_EXT_IA_STR 2
typedef const char* (*ia_str_t)(iaddr ia);

#define DNSCAP_EXT_TCPSTATE_GETCURR 3
typedef void* (*tcpstate_getcurr_t)(void);

#define DNSCAP_EXT_TCPSTATE_RESET 4
typedef void (*tcpstate_reset_t)(void* tcpstate, const char* msg);

#define DNSCAP_OUTPUT_ISFRAG (1 << 0)
#define DNSCAP_OUTPUT_ISDNS (1 << 1)
#define DNSCAP_OUTPUT_ISLAYER (1 << 2)

#define DIR_INITIATE 0x0001
#define DIR_RESPONSE 0x0002

#endif /* __dnscap_dnscap_common_h */
