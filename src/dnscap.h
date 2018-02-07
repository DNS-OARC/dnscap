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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/fcntl.h> /* for open() */
#include <sys/ioctl.h> /* for TIOCNOTTY */
#include <stdarg.h>
#include <syslog.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/resource.h>
#if HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef __linux__
#define __FAVOR_BSD
#define __USE_GNU
#define _GNU_SOURCE
#include <net/ethernet.h>
#ifdef USE_SECCOMP
#include <seccomp.h>
#endif
#endif

#ifdef __FreeBSD__
#include <net/ethernet.h>
#endif

#ifdef __NetBSD__
#include <net/ethertypes.h>
#include <net/if.h>
#include <net/if_ether.h>
#endif

#ifdef __OpenBSD__
#include <net/ethertypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#endif

#ifdef __APPLE__
#include <net/ethernet.h>
#include <net/bpf.h>
#endif

#ifdef __hpux
#include <net/if.h>
#include <netinet/if_ether.h>
#define ETHER_HDR_LEN ETHER_HLEN
#define __BIT_TYPES_DEFINED
#define __HPLX
#endif

#ifdef __SVR4
#include <stdarg.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "snprintf.h"
#define IP_OFFMASK 0x1fff
#define u_int32_t uint32_t
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN 14
#endif
#endif

#ifndef MY_BPFTIMEVAL
#define MY_BPFTIMEVAL timeval
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/nameser.h>
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pcap.h>
#include <regex.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#if HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifndef IPV6_VERSION
#define IPV6_VERSION 0x60
#endif
#ifndef IPV6_VERSION_MASK
#define IPV6_VERSION_MASK 0xf0
#endif

#define UDP10_QR_MASK 0x80
#define UDP10_QR_SHIFT 7
#define UDP10_OP_MASK 0x78
#define UDP10_OP_SHIFT 3
#define UDP10_AA_MASK 0x04
#define UDP10_AA_SHIFT 2
#define UDP10_TC_MASK 0x02
#define UDP10_TC_SHIFT 1
#define UDP10_RD_MASK 0x01
#define UDP10_RD_SHIFT 0

#define UDP11_RC_MASK 0x0f
#define UDP11_RC_SHIFT 0

#define MSG_QUERY 0x0001
#define MSG_UPDATE 0x0002
#define MSG_NOTIFY 0x0004

#define ERR_TRUNC 0x0001
#define ERR_RCODE_BASE 0x0002
#define ERR_NO (ERR_RCODE_BASE << ns_r_noerror)
#define ERR_FORMERR (ERR_RCODE_BASE << ns_r_formerr)
#define ERR_SERVFAIL (ERR_RCODE_BASE << ns_r_servfail)
#define ERR_NXDOMAIN (ERR_RCODE_BASE << ns_r_nxdomain)
#define ERR_NOTIMPL (ERR_RCODE_BASE << ns_r_notimpl)
#define ERR_REFUSED (ERR_RCODE_BASE << ns_r_refused)
#define ERR_YES (0xffffffff & ~ERR_NO)

#define END_INITIATOR 0x0001
#define END_RESPONDER 0x0002

#define HIDE_INET "\177\177\177\177"
#define HIDE_INET6 "\177\177\177\177\177\177\177\177" \
                   "\177\177\177\177\177\177\177\177"
#define HIDE_PORT 54321

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#define THOUSAND 1000
#define MILLION (THOUSAND * THOUSAND)
#define MAX_VLAN 4095
#define DNS_PORT 53
#define TO_MS 1
#define SNAPLEN 65536
#define TRUE 1
#define FALSE 0
#define REGEX_CFLAGS (REG_EXTENDED | REG_ICASE | REG_NOSUB | REG_NEWLINE)
#define MAX_TCP_WINDOW (0xFFFF << 14)
#define MEM_MAX 20000000000 /* SETTING MAX MEMORY USAGE TO 2GB */

#define ISC_CHECK_NONE 1
#include "isc/list.h"
#include "isc/assertions.h"

#include "dnscap_common.h"

#include "dump_dns.h"
#include "dump_cbor.h"
#include "dump_cds.h"
#include "options.h"
#include "pcap-thread/pcap_thread.h"

#ifndef __dnscap_dnscap_h
#define __dnscap_dnscap_h

struct text {
    LINK(struct text)
    link;
    size_t len;
    char*  text;
};
typedef struct text* text_ptr;
typedef LIST(struct text) text_list;
#define text_size(len) (sizeof(struct text) + len)

struct mypcap {
    LINK(struct mypcap)
    link;
    const char*      name;
    struct pcap_stat ps0, ps1;
    uint64_t         drops;
};
typedef struct mypcap* mypcap_ptr;
typedef LIST(struct mypcap) mypcap_list;

struct vlan {
    LINK(struct vlan)
    link;
    unsigned vlan;
};
typedef struct vlan* vlan_ptr;
typedef LIST(struct vlan) vlan_list;

#define MAX_TCP_WINDOW_SIZE (0xFFFF << 14)
#define MAX_TCP_MSGS 8
#define MAX_TCP_SEGS 8
#define MAX_TCP_HOLES 8
#define MAX_TCP_DNS_MSG 8

typedef struct tcphole    tcphole_t;
typedef struct tcp_msgbuf tcp_msgbuf_t;
typedef struct tcp_segbuf tcp_segbuf_t;
typedef struct tcpdnsmsg  tcpdnsmsg_t;
typedef struct tcpreasm   tcpreasm_t;

struct tcphole {
    uint16_t start;
    uint16_t len;
};

struct tcp_msgbuf {
    uint32_t  seq;
    uint16_t  dnslen;
    tcphole_t hole[MAX_TCP_HOLES];
    int       holes;
    u_char    buf[];
};

struct tcp_segbuf {
    uint32_t seq;
    uint16_t len;
    u_char   buf[];
};

struct tcpdnsmsg {
    size_t   segments_seen;
    uint16_t dnslen;
    u_char   dnspkt[];
};

struct tcpreasm {
    uint32_t      seq_start;
    size_t        msgbufs;
    u_char        dnslen_buf[2];
    u_char        dnslen_bytes_seen_mask;
    tcp_msgbuf_t* msgbuf[MAX_TCP_MSGS];
    tcp_segbuf_t* segbuf[MAX_TCP_SEGS];
    size_t        segments_seen;
    size_t        dnsmsgs;
    tcpdnsmsg_t*  dnsmsg[MAX_TCP_DNS_MSG];
    uint32_t      seq_bfb;
    tcp_segbuf_t* bfb_seg[MAX_TCP_SEGS];
    u_char*       bfb_buf;
    size_t        bfb_at;
};

struct tcpstate {
    LINK(struct tcpstate)
    link;
    iaddr    saddr;
    iaddr    daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t start; /* seq# of tcp payload start */
    uint32_t maxdiff; /* maximum (seq# - start) */
    uint16_t dnslen;
    time_t   last_use;
    uint32_t lastdns;
    uint32_t currseq;
    size_t   currlen;

    tcpreasm_t* reasm;
    size_t      reasm_faults;
};
typedef struct tcpstate* tcpstate_ptr;
typedef LIST(struct tcpstate) tcpstate_list;

struct endpoint {
    LINK(struct endpoint)
    link;
    iaddr ia;
};
typedef struct endpoint* endpoint_ptr;
typedef LIST(struct endpoint) endpoint_list;

struct myregex {
    LINK(struct myregex)
    link;
    regex_t reg;
    char*   str;
    int not;
};
typedef struct myregex* myregex_ptr;
typedef LIST(struct myregex) myregex_list;

struct plugin {
    LINK(struct plugin)
    link;

    char* name;
    void* handle;

    int (*start)(logerr_t*);
    void (*stop)();
    int (*open)(my_bpftimeval);
    int (*close)();
    output_t(*output);
    void (*getopt)(int*, char** []);
    void (*usage)();
    void (*extension)(int, void*);
};
typedef LIST(struct plugin) plugin_list;

enum dump_type {
    nowhere,
    to_stdout,
    to_file
};
enum dump_state {
    dumper_opened,
    dumper_closed
};

extern plugin_list plugins;
extern const char* ProgramName;
extern char*       dump_suffix;
extern int         wantgzip;

extern plugin_list     plugins;
extern const char*     ProgramName;
extern int             dumptrace;
extern int             flush;
extern vlan_list       vlans_excl;
extern vlan_list       vlans_incl;
extern unsigned        msg_wanted;
extern unsigned        dir_wanted;
extern unsigned        end_hide;
extern unsigned        err_wanted;
extern tcpstate_list   tcpstates;
extern int             tcpstate_count;
extern endpoint_list   initiators, not_initiators;
extern endpoint_list   responders, not_responders;
extern endpoint_list   drop_responders;
extern myregex_list    myregexes;
extern mypcap_list     mypcaps;
extern mypcap_ptr      pcap_offline;
extern const char*     dump_base;
extern char*           dump_suffix;
extern char*           extra_bpf;
extern enum dump_type  dump_type;
extern enum dump_state dump_state;
extern const char*     kick_cmd;
extern unsigned        limit_seconds;
extern time_t          next_interval;
extern unsigned        limit_packets;
extern size_t          limit_pcapfilesize;
extern pcap_t*         pcap_dead;
extern pcap_dumper_t*  dumper;
extern time_t          dumpstart;
extern unsigned        msgcount;
extern size_t          capturedbytes;
extern char *          dumpname, *dumpnamepart;
extern char*           bpft;
extern unsigned        dns_port;
extern int             promisc;
extern int             monitor_mode;
extern int             immediate_mode;
extern int             background;
extern char            errbuf[PCAP_ERRBUF_SIZE];
extern int             v6bug;
extern int             wantgzip;
extern int             wantfrags;
extern int             wanticmp;
extern int             wanttcp;
extern int             preso;
#ifdef USE_SECCOMP
extern int use_seccomp;
#endif
extern int                main_exit;
extern int                alarm_set;
extern time_t             start_time;
extern time_t             stop_time;
extern int                print_pcap_stats;
extern uint64_t           pcap_drops;
extern my_bpftimeval      last_ts;
extern unsigned long long mem_limit;
extern int                mem_limit_set;
extern const char         DROPTOUSER[];
extern pcap_thread_t      pcap_thread;
extern int                only_offline_pcaps;
extern int                dont_drop_privileges;
extern options_t          options;

#endif /* __dnscap_dnscap_h */
