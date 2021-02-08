/*
 * Copyright (c) 2016-2020, OARC, Inc.
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

#include "network.h"
#include "iaddr.h"
#include "log.h"
#include "pcaps.h"
#include "dumper.h"
#include "endpoint.h"
#include "tcpstate.h"
#include "tcpreasm.h"
#include "endian_compat.h"

#include <ldns/ldns.h>

struct ip6_hdr* network_ipv6 = 0;
struct ip*      network_ip   = 0;
struct udphdr*  network_udp  = 0;

extern tcpstate_ptr _curr_tcpstate; /* from tcpstate.c */

static inline uint16_t _need16(const void* ptr)
{
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return be16toh(v);
}

static inline uint32_t _need32(const void* ptr)
{
    uint32_t v;
    memcpy(&v, ptr, sizeof(v));
    return be32toh(v);
}

static int skip_vlan(unsigned vlan)
{
    if (!EMPTY(vlans_excl)) {
        vlan_ptr vl;

        for (vl = HEAD(vlans_excl); vl != NULL; vl = NEXT(vl, link)) {
            if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
                break;
        }

        /*
         * If there is no VLAN matching the packet, skip it
         */
        if (vl == NULL)
            return 1;
    } else if (!EMPTY(vlans_incl)) {
        vlan_ptr vl;

        for (vl = HEAD(vlans_incl); vl != NULL; vl = NEXT(vl, link)) {
            if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
                break;
        }

        /*
         * If there is no VLAN matching the packet, and the packet is tagged, skip it
         */
        if (vl == NULL && vlan != MAX_VLAN)
            return 1;
    }

    return 0;
}

void layer_pkt(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    mypcap_ptr                  mypcap = (mypcap_ptr)user;
    size_t                      len;
    unsigned                    vlan;
    const pcap_thread_packet_t *prevpkt, *firstpkt = packet;
    char                        descr[200];

    if (!mypcap)
        return;
    if (!packet)
        return;

    while (firstpkt->have_prevpkt) {
        if (firstpkt->have_pkthdr)
            break;
        firstpkt = firstpkt->prevpkt;
    }
    if (!firstpkt->have_pkthdr)
        return;

    if (only_offline_pcaps && start_time != 0 && firstpkt->pkthdr.ts.tv_sec < start_time)
        return;

    len = firstpkt->pkthdr.caplen;

    last_ts = firstpkt->pkthdr.ts;
    if (stop_time != 0 && firstpkt->pkthdr.ts.tv_sec >= stop_time) {
        breakloop_pcaps();
        main_exit = TRUE;
    }

    if (main_exit)
        return;

    /* If ever SNAPLEN wasn't big enough, we have no recourse. */
    if (firstpkt->pkthdr.len != firstpkt->pkthdr.caplen)
        return;

    vlan = MAX_VLAN;
    for (prevpkt = packet; prevpkt; prevpkt = prevpkt->prevpkt) {
        if (prevpkt->have_ieee802hdr) {
            /* TODO: Only match first found VLAN or all? */
            vlan = prevpkt->ieee802hdr.vid;
            len -= 4;
            break;
        }
        if (!prevpkt->have_prevpkt)
            break;
    }
    if (skip_vlan(vlan)) {
        return;
    }

    descr[0] = 0;
    if (preso) {
        char      when[100];
        struct tm tm;
        time_t    t;

        /*
         * Reduce `len` to report same captured length as `dl_pkt`
         */
        for (prevpkt = packet; len && prevpkt; prevpkt = prevpkt->prevpkt) {
            if (prevpkt->have_nullhdr) {
                if (len > sizeof(prevpkt->nullhdr))
                    len -= sizeof(prevpkt->nullhdr);
                else
                    len = 0;
            }
            if (prevpkt->have_loophdr) {
                if (len > sizeof(prevpkt->loophdr))
                    len -= sizeof(prevpkt->loophdr);
                else
                    len = 0;
            }
            if (prevpkt->have_ethhdr) {
                if (len > sizeof(prevpkt->ethhdr))
                    len -= sizeof(prevpkt->ethhdr);
                else
                    len = 0;
            }
            if (prevpkt->have_linux_sll) {
                if (len > sizeof(prevpkt->linux_sll))
                    len -= sizeof(prevpkt->linux_sll);
                else
                    len = 0;
            }

            if (!prevpkt->have_prevpkt)
                break;
        }

        t = (time_t)firstpkt->pkthdr.ts.tv_sec;
        gmtime_r(&t, &tm);
        strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);

        if (vlan != MAX_VLAN) {
            snprintf(descr, sizeof(descr), "[%lu] %s.%06lu [#%ld %s (vlan %u) %u] \\\n",
                (u_long)len,
                when,
                (u_long)firstpkt->pkthdr.ts.tv_usec,
                (long)msgcount,
                mypcap->name ? mypcap->name : "\"some interface\"",
                vlan,
                vlan);
        } else {
            snprintf(descr, sizeof(descr), "[%lu] %s.%06lu [#%ld %s %u] \\\n",
                (u_long)len,
                when,
                (u_long)firstpkt->pkthdr.ts.tv_usec,
                (long)msgcount,
                mypcap->name ? mypcap->name : "\"some interface\"",
                vlan);
        }
    }

    if (next_interval != 0 && firstpkt->pkthdr.ts.tv_sec >= next_interval && dumper_opened == dump_state)
        dumper_close(firstpkt->pkthdr.ts);
    if (dumper_closed == dump_state && dumper_open(firstpkt->pkthdr.ts))
        goto breakloop;

    network_pkt2(descr, firstpkt->pkthdr.ts, packet, payload, length);

    if (limit_packets != 0U && msgcount == limit_packets) {
        if (preso)
            goto breakloop;
        if (dumper_opened == dump_state && dumper_close(firstpkt->pkthdr.ts))
            goto breakloop;
        msgcount = 0;
    }

    if (limit_pcapfilesize != 0U && capturedbytes >= limit_pcapfilesize) {
        if (preso) {
            goto breakloop;
        }
        if (dumper_opened == dump_state && dumper_close(firstpkt->pkthdr.ts)) {
            goto breakloop;
        }
        capturedbytes = 0;
    }

    return;
breakloop:
    breakloop_pcaps();
    main_exit = TRUE;
}

void dl_pkt(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt, const char* name, const int dlt)
{
    mypcap_ptr mypcap = (mypcap_ptr)user;
    size_t     len    = hdr->caplen;
    unsigned   etype, vlan, pf;
    char       descr[512];

    if (only_offline_pcaps && start_time != 0 && hdr->ts.tv_sec < start_time)
        return;

    last_ts = hdr->ts;
    if (stop_time != 0 && hdr->ts.tv_sec >= stop_time) {
        breakloop_pcaps();
        main_exit = TRUE;
    }

    if (main_exit)
        return;

    /* If ever SNAPLEN wasn't big enough, we have no recourse. */
    if (hdr->len != hdr->caplen)
        return;

    /* Data link. */
    vlan = MAX_VLAN; /* MAX_VLAN (0xFFF) is reserved and shouldn't appear on the wire */
    switch (dlt) {
    case DLT_NULL: {
        uint32_t x;

        if (len < 4)
            return;
        x = _need32(pkt);
        if (x == PF_INET)
            etype = ETHERTYPE_IP;
        else if (x == PF_INET6)
            etype = ETHERTYPE_IPV6;
        else
            return;
        pkt += 4;
        len -= 4;
        break;
    }
    case DLT_LOOP: {
        uint32_t x;

        if (len < 4)
            return;
        x = _need32(pkt);
        if (x == PF_INET)
            etype = ETHERTYPE_IP;
        else if (x == PF_INET6)
            etype = ETHERTYPE_IPV6;
        else
            return;
        pkt += 4;
        len -= 4;
        break;
    }
    case DLT_RAW: {
        if (len < 1)
            return;
        switch (*(const uint8_t*)pkt >> 4) {
        case 4:
            etype = ETHERTYPE_IP;
            break;
        case 6:
            etype = ETHERTYPE_IPV6;
            break;
        default:
            return;
        }
        break;
    }
    case DLT_EN10MB: {
        const struct ether_header* ether;

        if (len < ETHER_HDR_LEN)
            return;
        ether = (const struct ether_header*)pkt;
        etype = ntohs(ether->ether_type);
        pkt += ETHER_HDR_LEN;
        len -= ETHER_HDR_LEN;
        if (etype == ETHERTYPE_VLAN) {
            if (len < 4)
                return;
            vlan = _need16(pkt) & 0xFFF;
            pkt += 2;
            len -= 2;
            etype = _need16(pkt);
            pkt += 2;
            len -= 2;
        }
        break;
    }
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL: {
        if (len < 16)
            return;
        etype = _need16(&pkt[14]);
        pkt += 16;
        len -= 16;
        break;
    }
#endif
    default:
        return;
    }

    if (!EMPTY(vlans_excl)) {
        vlan_ptr vl;

        for (vl = HEAD(vlans_excl);
             vl != NULL;
             vl = NEXT(vl, link))
            if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
                break;
        /*
         * If there is no VLAN matching the packet, skip it
         */
        if (vl == NULL)
            return;
    } else if (!EMPTY(vlans_incl)) {
        vlan_ptr vl;

        for (vl = HEAD(vlans_incl);
             vl != NULL;
             vl = NEXT(vl, link))
            if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
                break;
        /*
         * If there is no VLAN matching the packet, and the packet is tagged, skip it
         */
        if (vl == NULL && vlan != MAX_VLAN)
            return;
    }

    switch (etype) {
    case ETHERTYPE_IP:
        pf = PF_INET;
        break;
    case ETHERTYPE_IPV6:
        pf = PF_INET6;
        break;
    default:
        return;
    }

    if (preso) {
        char        when[100], via[100];
        const char* viap;
        struct tm   tm;
        time_t      t;

        t = (time_t)hdr->ts.tv_sec;
        gmtime_r(&t, &tm);
        strftime(when, sizeof when, "%Y-%m-%d %T", &tm);
        if (vlan != MAX_VLAN) {
            snprintf(via, sizeof(via), "%s (vlan %u)", mypcap->name ? mypcap->name : "\"some interface\"", vlan);
            viap = via;
        } else if (mypcap->name) {
            viap = mypcap->name;
        } else {
            viap = "\"some interface\"";
        }
        snprintf(descr, sizeof(descr), "[%lu] %s.%06lu [#%ld %s %u] \\\n",
            (u_long)len, when, (u_long)hdr->ts.tv_usec, (long)msgcount, viap, vlan);
    } else {
        descr[0] = '\0';
    }

    if (next_interval != 0 && hdr->ts.tv_sec >= next_interval && dumper_opened == dump_state)
        dumper_close(hdr->ts);
    if (dumper_closed == dump_state && dumper_open(hdr->ts))
        goto breakloop;

    network_pkt(descr, hdr->ts, pf, pkt, len);

    if (limit_packets != 0U && msgcount == limit_packets) {
        if (preso)
            goto breakloop;
        if (dumper_opened == dump_state && dumper_close(hdr->ts))
            goto breakloop;
        msgcount = 0;
    }

    if (limit_pcapfilesize != 0U && capturedbytes >= limit_pcapfilesize) {
        if (preso) {
            goto breakloop;
        }
        if (dumper_opened == dump_state && dumper_close(hdr->ts)) {
            goto breakloop;
        }
        capturedbytes = 0;
    }

    return;
breakloop:
    breakloop_pcaps();
    main_exit = TRUE;
}

void network_pkt2(const char* descr, my_bpftimeval ts, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    u_char        pkt_copy[SNAPLEN], *pkt = pkt_copy;
    const u_char* dnspkt = 0;
    unsigned      proto, sport, dport;
    iaddr         from, to, initiator, responder;
    int           response, m;
    unsigned      flags    = DNSCAP_OUTPUT_ISLAYER;
    tcpstate_ptr  tcpstate = NULL;
    size_t        len, dnslen = 0;
    HEADER        dns;
    ldns_pkt*     lpkt = 0;

    /* Make a writable copy of the packet and use that copy from now on. */
    if (length > SNAPLEN)
        return;
    memcpy(pkt, payload, len = length);

    /* Network. */
    sport = dport = 0;
    if (packet->have_iphdr) {
        if (dumptrace >= 4)
            fprintf(stderr, "processing IPv4 packet: len=%zu\n", length);

        memset(&from, 0, sizeof from);
        from.af = AF_INET;
        memcpy(&from.u.a4, &(packet->iphdr.ip_src), sizeof(struct in_addr));
        memset(&to, 0, sizeof to);
        to.af = AF_INET;
        memcpy(&to.u.a4, &(packet->iphdr.ip_dst), sizeof(struct in_addr));
    } else if (packet->have_ip6hdr) {
        if (dumptrace >= 4)
            fprintf(stderr, "processing IPv6 packet: len=%zu\n", length);

        memset(&from, 0, sizeof from);
        from.af = AF_INET6;
        memcpy(&from.u.a6, &(packet->ip6hdr.ip6_src), sizeof(struct in6_addr));
        memset(&to, 0, sizeof to);
        to.af = AF_INET6;
        memcpy(&to.u.a6, &(packet->ip6hdr.ip6_dst), sizeof(struct in6_addr));
    } else {
        if (dumptrace >= 4)
            fprintf(stderr, "processing unknown packet: len=%zu\n", length);
        from.af = AF_UNSPEC;
        to.af   = AF_UNSPEC;
    }

    /* Transport. */
    if (packet->have_icmphdr) {
        output(descr, from, to, IPPROTO_ICMP, flags, sport, dport, ts, pkt_copy, length, pkt, len);
        return;
    } else if (packet->have_icmpv6hdr) {
        output(descr, from, to, IPPROTO_ICMPV6, flags, sport, dport, ts, pkt_copy, length, pkt, len);
        return;
    } else if (packet->have_udphdr) {
        proto  = IPPROTO_UDP;
        sport  = packet->udphdr.uh_sport;
        dport  = packet->udphdr.uh_dport;
        dnspkt = payload;
        dnslen = length;
        flags |= DNSCAP_OUTPUT_ISDNS;
    } else if (packet->have_tcphdr) {
        uint32_t seq = packet->tcphdr.th_seq;

        proto = IPPROTO_TCP;
        sport = packet->tcphdr.th_sport;
        dport = packet->tcphdr.th_dport;

        /*
         * TCP processing.
         *
         * We need to capture enough to allow a later analysis to
         * reassemble the TCP stream, but we don't want to keep all
         * the state required to do reassembly here.
         * When we get a SYN, we don't yet know if the DNS message
         * will pass the filters, so we always output it, and also
         * generate a tcpstate to keep track of the stream.  (An
         * alternative would be to store the SYN packet on the
         * tcpstate and not output it until a later packet passes the
         * filter, but that would require more memory and would
         * reorder packets in the pcap output.)
         * When we get the _first_ DNS header on the stream, then we
         * can apply the DNS header filters; if the packet passes, we
         * output the packet and keep the tcpstate; if it fails, we
         * discard the packet and the tcpstate.
         * When we get any other packet with DNS payload, we output it
         * only if there is a corresponding tcpstate indicating that
         * the header passed the filters.
         * Packets with no TCP payload (e.g., packets containing only
         * an ACK) are discarded, since they carry no DNS information
         * and are not needed for stream reassembly.
         * FIN packets are always output to match the SYN, even if the
         * DNS header failed the filter, to be friendly to later
         * analysis programs that allocate state for each SYN.
         * -- kkeys@caida.org
         */

        tcpstate = tcpstate_find(from, to, sport, dport, ts.tv_sec);
        if (dumptrace >= 3) {
            fprintf(stderr, "%s: tcp pkt: %lu.%06lu [%4lu] %15s -> ",
                ProgramName,
                (u_long)ts.tv_sec,
                (u_long)ts.tv_usec,
                (u_long)len,
                ia_str(from));
            fprintf(stderr, "%15s; ", ia_str(to));

            if (tcpstate)
                fprintf(stderr, "want=%08x; ", tcpstate->start);
            else
                fprintf(stderr, "no state; ");

            fprintf(stderr, "seq=%08x; ", seq);
        }
        if (packet->tcphdr.th_flags & (TH_FIN | TH_RST)) {
            if (dumptrace >= 3)
                fprintf(stderr, "FIN|RST\n");

            /* Always output FIN and RST segments. */
            _curr_tcpstate = tcpstate;
            output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
            _curr_tcpstate = 0;

            /* End of stream; deallocate the tcpstate. */
            if (tcpstate) {
                UNLINK(tcpstates, tcpstate, link);
                if (tcpstate->reasm) {
                    tcpreasm_free(tcpstate->reasm);
                }
                free(tcpstate);
                tcpstate_count--;
            }
            return;
        }
        if (packet->tcphdr.th_flags & TH_SYN) {
            if (dumptrace >= 3)
                fprintf(stderr, "SYN\n");

            if (tcpstate) {
                if (tcpstate->start == seq + 1) {
                    /* repeated SYN */
                } else {
                    /* Assume existing state is stale and recycle it. */

                    /*
                     * Disabled because warning may scare user, and
                     * there's nothing else we can do anyway.
                     */

                    /*
                    if (ts.tv_sec - tcpstate->last_use < MAX_TCP_IDLE_TIME)
                    fprintf(stderr, "warning: recycling state for "
                        "duplicate tcp stream after only %ld "
                        "seconds idle\n",
                        (u_long)(ts.tv_sec - tcpstate->last_use));
                    */
                }
            } else {
                /* create new tcpstate */
                tcpstate = tcpstate_new(from, to, sport, dport);
            }
            tcpstate->last_use = ts.tv_sec;
            tcpstate->start    = seq + 1; /* add 1 for the SYN */
            tcpstate->maxdiff  = 1;
            tcpstate->dnslen   = 0;
            tcpstate->lastdns  = 0;

            /* Always output SYN segments. */
            _curr_tcpstate = tcpstate;
            output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
            _curr_tcpstate = 0;

            return;
        }
        if (options.parse_ongoing_tcp && !tcpstate && len) {
            tcpstate           = tcpstate_new(from, to, sport, dport);
            tcpstate->last_use = ts.tv_sec;
            tcpstate->start    = seq;
            tcpstate->maxdiff  = 0;
            tcpstate->dnslen   = 0;
            tcpstate->lastdns  = seq;
        }
        if (tcpstate && options.reassemble_tcp) {
            if (!tcpstate->reasm) {
                if (!(tcpstate->reasm = calloc(1, sizeof(tcpreasm_t)))) {
                    logerr("out of memory, TCP reassembly failed");
                    return;
                }
                tcpstate->reasm->seq_start = tcpstate->start;
                tcpstate->reasm->seq_bfb   = tcpstate->start;
            }
            if (options.allow_reset_tcpstate) {
                if (tcpstate->reasm_faults > options.reassemble_tcp_faultreset) {
                    if (dumptrace >= 3)
                        fprintf(stderr, "fault reset ");
                    tcpstate_reset(tcpstate, "too many reassembly faults");
                    tcpstate->reasm->seq_start = seq;
                    tcpstate->reasm->seq_bfb   = seq;
                    tcpstate->reasm_faults     = 0;
                }
                if (dumptrace >= 3)
                    fprintf(stderr, "reassemble\n");
                if (pcap_handle_tcp_segment(pkt, len, seq, tcpstate)) {
                    tcpstate->reasm_faults++;
                }
            } else {
                if (dumptrace >= 3)
                    fprintf(stderr, "reassemble\n");
                (void)pcap_handle_tcp_segment(pkt, len, seq, tcpstate);
            }
        } else if (tcpstate) {
            uint32_t seqdiff = seq - tcpstate->start;

            tcpstate->currseq = seq;
            tcpstate->currlen = len;

            if (options.allow_reset_tcpstate && tcpstate->lastdns && seq > tcpstate->lastdns + 2) {
                /*
                 * seq received is beyond where we expect next DNS message
                 * to be, reset tcpstate and continue
                 */
                tcpstate->maxdiff = 0;
                tcpstate->dnslen  = 0;
                tcpstate->lastdns = seq;
            }

            if (dumptrace >= 3)
                fprintf(stderr, "diff=%08x; lastdns=%08x; ", seqdiff, tcpstate->lastdns);

            if (tcpstate->lastdns && seq == tcpstate->lastdns && len > 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+len+hdr\n");
                dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
                dnspkt                    = pkt + 2;
                if (dnslen > len - 2)
                    dnslen = len - 2;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->maxdiff = (uint32_t)len;
                tcpstate->lastdns = seq + 2 + tcpstate->dnslen;
            } else if (tcpstate->lastdns && seq == tcpstate->lastdns && len == 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+len\n");
                tcpstate->dnslen  = (pkt[0] << 8) | (pkt[1] << 0);
                tcpstate->maxdiff = (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
                _curr_tcpstate = 0;
                return;
            } else if (tcpstate->lastdns && ((seq == tcpstate->lastdns && len == 1) || seqdiff == 1)) {
                tcpstate_discard(tcpstate, NULL);
                return;
            } else if (tcpstate->lastdns && seq == tcpstate->lastdns + 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+hdr\n");
                tcpstate->maxdiff = seqdiff + (uint32_t)len;
                dnslen            = tcpstate->dnslen;
                dnspkt            = pkt;
                if (dnslen == 0) /* we never received it */
                    dnslen = len;
                if (dnslen > len)
                    dnslen = len;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->lastdns = seq + tcpstate->dnslen;
            } else if (seqdiff == 0 && len > 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "len+hdr\n");

                /*
                 * This is the first segment of the stream, and
                 * contains the dnslen and dns header, so we can
                 * filter on it.
                 */
                dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
                dnspkt                    = pkt + 2;
                if (dnslen > len - 2)
                    dnslen = len - 2;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->maxdiff = (uint32_t)len;
                tcpstate->lastdns = seq + 2 + tcpstate->dnslen;
            } else if (seqdiff == 0 && len == 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "len\n");

                /*
                 * This is the first segment of the stream, but only
                 * contains the dnslen.
                 */
                tcpstate->dnslen  = (pkt[0] << 8) | (pkt[1] << 0);
                tcpstate->maxdiff = (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
                _curr_tcpstate = 0;
                return;
            } else if ((seqdiff == 0 && len == 1) || seqdiff == 1) {
                /* shouldn't happen */
                tcpstate_discard(tcpstate, NULL);
                return;
            } else if (seqdiff == 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "hdr\n");

                /*
                 * This is not the first segment, but it does contain
                 * the first dns header, so we can filter on it.
                 */
                tcpstate->maxdiff = seqdiff + (uint32_t)len;
                dnslen            = tcpstate->dnslen;
                dnspkt            = pkt;
                if (dnslen == 0) /* we never received it */
                    dnslen = len;
                if (dnslen > len)
                    dnslen = len;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->lastdns = seq + tcpstate->dnslen;
            } else if (seqdiff > tcpstate->maxdiff + MAX_TCP_WINDOW) {
                if (dumptrace >= 3)
                    fprintf(stderr, "out of window\n");

                /* This segment is outside the window. */
                return;
            } else if (len == 0) {
                if (dumptrace >= 3)
                    fprintf(stderr, "empty\n");

                /* No payload (e.g., an ACK) */
                return;
            } else {
                if (dumptrace >= 3)
                    fprintf(stderr, "keep\n");

                /* non-first */
                if (tcpstate->maxdiff < seqdiff + (uint32_t)len)
                    tcpstate->maxdiff = seqdiff + (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
                _curr_tcpstate = 0;
                return;
            }
        } else {
            if (dumptrace >= 3)
                fprintf(stderr, "no state\n");

            /*
             * There is no state for this stream.  Either we never saw
             * a SYN for this stream, or we have already decided to
             * discard this stream.
             */
            return;
        }
    } else {
        return;
    }

    for (m = 0; m < MAX_TCP_DNS_MSG; m++) {
        if (tcpstate && tcpstate->reasm) {
            if (!tcpstate->reasm->dnsmsg[m])
                continue;
            dnslen = tcpstate->reasm->dnsmsg[m]->dnslen;
            dnspkt = tcpstate->reasm->dnsmsg[m]->dnspkt;
            flags |= DNSCAP_OUTPUT_ISDNS;
            if (tcpstate->reasm->dnsmsg[m]->segments_seen > 1) {
                /* emulate dnslen in own packet */
                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, NULL, 0);
                _curr_tcpstate = 0;
            }
        }

        /* Application. */
        if (!dnspkt) {
            tcpstate_discard(tcpstate, "no dns");
            return;
        }
        if (dnslen < sizeof dns) {
            tcpstate_discard(tcpstate, "too small");
            return;
        }
        memcpy(&dns, dnspkt, sizeof dns);

        /* Policy filtering. */
        if (dns.qr == 0 && dport == dns_port) {
            if ((dir_wanted & DIR_INITIATE) == 0) {
                tcpstate_discard(tcpstate, "unwanted dir=i");
                return;
            }
            initiator = from;
            responder = to;
            response  = FALSE;
        } else if (dns.qr != 0 && sport == dns_port) {
            if ((dir_wanted & DIR_RESPONSE) == 0) {
                tcpstate_discard(tcpstate, "unwanted dir=r");
                return;
            }
            initiator = to;
            responder = from;
            response  = TRUE;
        } else {
            tcpstate_discard(tcpstate, "unwanted direction/port");
            return;
        }
        if ((!EMPTY(initiators) && !ep_present(&initiators, initiator)) || (!EMPTY(responders) && !ep_present(&responders, responder))) {
            tcpstate_discard(tcpstate, "unwanted host");
            return;
        }
        if ((!EMPTY(not_initiators) && ep_present(&not_initiators, initiator)) || (!EMPTY(not_responders) && ep_present(&not_responders, responder))) {
            tcpstate_discard(tcpstate, "missing required host");
            return;
        }
        if (!(((msg_wanted & MSG_QUERY) != 0 && dns.opcode == LDNS_PACKET_QUERY) || ((msg_wanted & MSG_UPDATE) != 0 && dns.opcode == LDNS_PACKET_UPDATE) || ((msg_wanted & MSG_NOTIFY) != 0 && dns.opcode == LDNS_PACKET_NOTIFY))) {
            tcpstate_discard(tcpstate, "unwanted opcode");
            return;
        }
        if (response) {
            int match_tc    = (dns.tc != 0 && err_wanted & ERR_TRUNC);
            int match_rcode = err_wanted & (ERR_RCODE_BASE << dns.rcode);

            if (!match_tc && !match_rcode) {
                tcpstate_discard(tcpstate, "unwanted error code");
                return;
            }
            if (!EMPTY(drop_responders) && ep_present(&drop_responders, responder)) {
                tcpstate_discard(tcpstate, "dropped response due to -Y");
                return;
            }
        }
        if (!EMPTY(myregexes) || match_qtype || nmatch_qtype) {
            if (ldns_wire2pkt(&lpkt, dnspkt, dnslen) != LDNS_STATUS_OK) {
                /* DNS message may have padding, try get actual size */
                size_t dnslen2 = calcdnslen(dnspkt, dnslen);
                if (dnslen2 > 0 && dnslen2 < dnslen) {
                    if (ldns_wire2pkt(&lpkt, dnspkt, dnslen2) != LDNS_STATUS_OK) {
                        tcpstate_discard(tcpstate, "failed parse");
                        return;
                    }
                } else {
                    tcpstate_discard(tcpstate, "failed parse");
                    return;
                }
            }
        }
        if (match_qtype || nmatch_qtype) {
            ldns_rr_list* rrs = ldns_pkt_question(lpkt);
            if (!rrs) {
                ldns_pkt_free(lpkt);
                tcpstate_discard(tcpstate, "failed to get list of questions");
                return;
            }
            /* Look at each RR in the section (or each QNAME in
               the question section). */
            size_t i, n;
            for (i = 0, n = ldns_rr_list_rr_count(rrs); i < n; i++) {
                ldns_rr* rr = ldns_rr_list_rr(rrs, i);
                if (!rr) {
                    ldns_pkt_free(lpkt);
                    tcpstate_discard(tcpstate, "failed to get question");
                    return;
                }

                if (match_qtype && ldns_rr_get_type(rr) != match_qtype) {
                    ldns_pkt_free(lpkt);
                    tcpstate_discard(tcpstate, "qtype not match");
                    return;
                } else if (nmatch_qtype && ldns_rr_get_type(rr) == nmatch_qtype) {
                    ldns_pkt_free(lpkt);
                    tcpstate_discard(tcpstate, "!qtype match");
                    return;
                }
            }
        }
        if (!EMPTY(myregexes)) {
            int          match, negmatch;
            ldns_buffer* buf = ldns_buffer_new(512);

            if (!buf) {
                fprintf(stderr, "%s: out of memory", ProgramName);
                exit(1);
            }

            match    = -1;
            negmatch = -1;
            /* Look at each section of the message:
                 question, answer, authority, additional */
            ldns_rr_list* rrs = ldns_pkt_all(lpkt);
            if (!rrs) {
                ldns_pkt_free(lpkt);
                ldns_buffer_free(buf);
                tcpstate_discard(tcpstate, "failed to get list of RRs");
                return;
            }
            /* Look at each RR in the section (or each QNAME in
               the question section). */
            size_t i, n;
            for (i = 0, n = ldns_rr_list_rr_count(rrs); i < n; i++) {
                ldns_rr* rr = ldns_rr_list_rr(rrs, i);
                if (!rr) {
                    ldns_rr_list_free(rrs);
                    ldns_pkt_free(lpkt);
                    ldns_buffer_free(buf);
                    tcpstate_discard(tcpstate, "failed to get RR");
                    return;
                }

                ldns_buffer_clear(buf);
                if (ldns_rdf2buffer_str(buf, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
                    ldns_rr_list_free(rrs);
                    ldns_pkt_free(lpkt);
                    ldns_buffer_free(buf);
                    tcpstate_discard(tcpstate, "failed to get RR");
                    return;
                }

                myregex_ptr myregex;
                for (myregex = HEAD(myregexes);
                     myregex != NULL;
                     myregex = NEXT(myregex, link)) {
                    if (myregex->not ) {
                        if (negmatch < 0)
                            negmatch = 0;
                    } else {
                        if (match < 0)
                            match = 0;
                    }

                    if (regexec(&myregex->reg, (char*)ldns_buffer_begin(buf), 0, NULL, 0) == 0) {
                        if (myregex->not )
                            negmatch++;
                        else
                            match++;

                        if (dumptrace >= 2)
                            fprintf(stderr,
                                "; \"%s\" %s~ /%s/ %d %d\n",
                                (char*)ldns_buffer_begin(buf),
                                myregex->not ? "!" : "",
                                myregex->str,
                                match,
                                negmatch);
                    }
                }
            }
            ldns_rr_list_free(rrs);
            ldns_buffer_free(buf);

            /*
             * Fail if any negative matching or if no match, match can be -1 which
             * indicates that there are only negative matching
             */
            if (negmatch > 0 || match == 0) {
                ldns_pkt_free(lpkt);
                tcpstate_discard(tcpstate, "failed regex match");
                return;
            }
        }
        if (lpkt) {
            ldns_pkt_free(lpkt);
        }

        /*
         * TODO: Policy hiding.
         */

        _curr_tcpstate = tcpstate;
        output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, length, dnspkt, dnslen);
        _curr_tcpstate = 0;

        if (tcpstate && tcpstate->reasm) {
            free(tcpstate->reasm->dnsmsg[m]);
            tcpstate->reasm->dnsmsg[m] = 0;
            tcpstate->reasm->dnsmsgs--;
        } else
            break;
    }
}

void network_pkt(const char* descr, my_bpftimeval ts, unsigned pf,
    const u_char* opkt, size_t olen)
{
    u_char          pkt_copy[SNAPLEN], *pkt = pkt_copy;
    const u_char*   dnspkt = 0;
    unsigned        proto, sport, dport;
    iaddr           from, to, initiator, responder;
    struct ip6_hdr* ipv6;
    int             response, m;
    unsigned        flags    = 0;
    struct udphdr*  udp      = NULL;
    struct tcphdr*  tcp      = NULL;
    tcpstate_ptr    tcpstate = NULL;
    struct ip*      ip;
    size_t          len, dnslen = 0;
    HEADER          dns;
    ldns_pkt*       lpkt = 0;

    if (dumptrace >= 4)
        fprintf(stderr, "processing %s packet: len=%zu\n", (pf == PF_INET ? "IPv4" : (pf == PF_INET6 ? "IPv6" : "unknown")), olen);

    /* Make a writable copy of the packet and use that copy from now on. */
    memcpy(pkt, opkt, len = olen);

    /* Network. */
    ip    = NULL;
    ipv6  = NULL;
    sport = dport = 0;
    switch (pf) {
    case PF_INET: {
        unsigned offset;

        if (len < sizeof *ip)
            return;
        network_ip = ip = (void*)pkt;
        network_ipv6    = 0;
        if (ip->ip_v != IPVERSION)
            goto network_pkt_end;
        proto = ip->ip_p;
        memset(&from, 0, sizeof from);
        from.af = AF_INET;
        memcpy(&from.u.a4, &ip->ip_src, sizeof(struct in_addr));
        memset(&to, 0, sizeof to);
        to.af = AF_INET;
        memcpy(&to.u.a4, &ip->ip_dst, sizeof(struct in_addr));
        offset = ip->ip_hl << 2;
        if (len > ntohs(ip->ip_len)) /* small IP packets have L2 padding */
            len = ntohs(ip->ip_len);
        if (len <= (size_t)offset)
            goto network_pkt_end;
        pkt += offset;
        len -= offset;
        offset = ntohs(ip->ip_off);
        if ((offset & IP_MF) != 0 || (offset & IP_OFFMASK) != 0) {
            if (wantfrags) {
                flags |= DNSCAP_OUTPUT_ISFRAG;
                output(descr, from, to, ip->ip_p, flags, sport, dport, ts, pkt_copy, olen, NULL, 0);
                goto network_pkt_end;
            }
            goto network_pkt_end;
        }
        break;
    }
    case PF_INET6: {
        uint16_t payload_len;
        uint8_t  nexthdr;
        unsigned offset;

        if (len < sizeof *ipv6)
            return;
        network_ipv6 = ipv6 = (void*)pkt;
        network_ip          = 0;
        if ((ipv6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
            goto network_pkt_end;

        nexthdr     = ipv6->ip6_nxt;
        offset      = sizeof(struct ip6_hdr);
        payload_len = ntohs(ipv6->ip6_plen);

        memset(&from, 0, sizeof from);
        from.af = AF_INET6;
        memcpy(&from.u.a6, &ipv6->ip6_src, sizeof(struct in6_addr));
        memset(&to, 0, sizeof to);
        to.af = AF_INET6;
        memcpy(&to.u.a6, &ipv6->ip6_dst, sizeof(struct in6_addr));

        while (nexthdr == IPPROTO_ROUTING || /* routing header */
               nexthdr == IPPROTO_HOPOPTS || /* Hop-by-Hop opts */
               nexthdr == IPPROTO_FRAGMENT || /* fragmentation hdr */
               nexthdr == IPPROTO_DSTOPTS || /* destination opts */
               nexthdr == IPPROTO_AH || /* destination opts */
               nexthdr == IPPROTO_ESP) /* encap sec payload */
        {
            struct {
                uint8_t nexthdr;
                uint8_t length;
            } ext_hdr;
            uint16_t ext_hdr_len;

            /* Catch broken packets */
            if ((offset + sizeof ext_hdr) > len)
                goto network_pkt_end;

            /* Cannot handle fragments. */
            if (nexthdr == IPPROTO_FRAGMENT) {
                if (wantfrags) {
                    flags |= DNSCAP_OUTPUT_ISFRAG;
                    output(descr, from, to, IPPROTO_FRAGMENT, flags, sport, dport, ts, pkt_copy, olen, NULL, 0);
                    goto network_pkt_end;
                }
                goto network_pkt_end;
            }

            memcpy(&ext_hdr, (u_char*)ipv6 + offset,
                sizeof ext_hdr);
            nexthdr     = ext_hdr.nexthdr;
            ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

            if (ext_hdr_len > payload_len)
                goto network_pkt_end;

            offset += ext_hdr_len;
            payload_len -= ext_hdr_len;
        }

        if ((offset + payload_len) > len || payload_len == 0)
            goto network_pkt_end;

        proto = nexthdr;
        pkt += offset;
        len -= offset;
        break;
    }
    default:
        goto network_pkt_end;
    }

    /* Transport. */
    switch (proto) {
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        network_udp = 0;
        output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, olen, pkt, len);
        goto network_pkt_end;
    case IPPROTO_UDP: {
        if (len < sizeof *udp)
            goto network_pkt_end;
        network_udp = udp = (void*)pkt;
        switch (from.af) {
        case AF_INET:
        case AF_INET6:
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
            break;
        default:
            abort();
        }
        pkt += sizeof *udp;
        len -= sizeof *udp;
        dnspkt = pkt;
        dnslen = len;
        flags |= DNSCAP_OUTPUT_ISDNS;
        break;
    }
    case IPPROTO_TCP: {
        network_udp = 0;

        /* TCP processing.
         * We need to capture enough to allow a later analysis to
         * reassemble the TCP stream, but we don't want to keep all
         * the state required to do reassembly here.
         * When we get a SYN, we don't yet know if the DNS message
         * will pass the filters, so we always output it, and also
         * generate a tcpstate to keep track of the stream.  (An
         * alternative would be to store the SYN packet on the
         * tcpstate and not output it until a later packet passes the
         * filter, but that would require more memory and would
         * reorder packets in the pcap output.)
         * When we get the _first_ DNS header on the stream, then we
         * can apply the DNS header filters; if the packet passes, we
         * output the packet and keep the tcpstate; if it fails, we
         * discard the packet and the tcpstate.
         * When we get any other packet with DNS payload, we output it
         * only if there is a corresponding tcpstate indicating that
         * the header passed the filters.
         * Packets with no TCP payload (e.g., packets containing only
         * an ACK) are discarded, since they carry no DNS information
         * and are not needed for stream reassembly.
         * FIN packets are always output to match the SYN, even if the
         * DNS header failed the filter, to be friendly to later
         * analysis programs that allocate state for each SYN.
         * -- kkeys@caida.org
         */
        unsigned offset;
        uint32_t seq;
        if (!wanttcp)
            goto network_pkt_end;
        if (len < sizeof *tcp)
            goto network_pkt_end;
        tcp = (void*)pkt;
        switch (from.af) {
        case AF_INET:
        case AF_INET6:
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
            seq   = ntohl(tcp->th_seq);
            break;
        default:
            abort();
        }
        offset = tcp->th_off * 4;
        pkt += offset;
        len -= offset;

        tcpstate = tcpstate_find(from, to, sport, dport, ts.tv_sec);
        if (dumptrace >= 3) {
            fprintf(stderr, "%s: tcp pkt: %lu.%06lu [%4lu] ", ProgramName,
                (u_long)ts.tv_sec, (u_long)ts.tv_usec, (u_long)len);
            fprintf(stderr, "%15s -> ", ia_str(from));
            fprintf(stderr, "%15s; ", ia_str(to));
            if (tcpstate)
                fprintf(stderr, "want=%08x; ", tcpstate->start);
            else
                fprintf(stderr, "no state; ");
            fprintf(stderr, "seq=%08x; ", seq);
        }
        if (tcp->th_flags & (TH_FIN | TH_RST)) {
            /* Always output FIN and RST segments. */
            if (dumptrace >= 3)
                fprintf(stderr, "FIN|RST\n");
            _curr_tcpstate = tcpstate;
            output(descr, from, to, proto, flags, sport, dport, ts,
                pkt_copy, olen, NULL, 0);
            _curr_tcpstate = 0;
            /* End of stream; deallocate the tcpstate. */
            if (tcpstate) {
                UNLINK(tcpstates, tcpstate, link);
                if (tcpstate->reasm) {
                    tcpreasm_free(tcpstate->reasm);
                }
                free(tcpstate);
                tcpstate_count--;
            }
            goto network_pkt_end;
        }
        if (tcp->th_flags & TH_SYN) {
            if (dumptrace >= 3)
                fprintf(stderr, "SYN\n");
            if (tcpstate) {
#if 0
            /* Disabled because warning may scare user, and
             * there's nothing else we can do anyway. */
            if (tcpstate->start == seq + 1) {
                /* repeated SYN */
            } else {
                /* Assume existing state is stale and recycle it. */
                if (ts.tv_sec - tcpstate->last_use < MAX_TCP_IDLE_TIME)
                fprintf(stderr, "warning: recycling state for "
                    "duplicate tcp stream after only %ld "
                    "seconds idle\n",
                    (u_long)(ts.tv_sec - tcpstate->last_use));
            }
#endif
            } else {
                /* create new tcpstate */
                tcpstate = tcpstate_new(from, to, sport, dport);
            }
            tcpstate->last_use = ts.tv_sec;
            tcpstate->start    = seq + 1; /* add 1 for the SYN */
            tcpstate->maxdiff  = 1;
            tcpstate->dnslen   = 0;
            tcpstate->lastdns  = 0;

            /* Always output SYN segments. */
            _curr_tcpstate = tcpstate;
            output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, olen, NULL, 0);
            _curr_tcpstate = 0;

            goto network_pkt_end;
        }
        if (options.parse_ongoing_tcp && !tcpstate && len) {
            tcpstate           = tcpstate_new(from, to, sport, dport);
            tcpstate->last_use = ts.tv_sec;
            tcpstate->start    = seq;
            tcpstate->maxdiff  = 0;
            tcpstate->dnslen   = 0;
            tcpstate->lastdns  = seq;
        }
        if (tcpstate && options.reassemble_tcp) {
            if (!tcpstate->reasm) {
                if (!(tcpstate->reasm = calloc(1, sizeof(tcpreasm_t)))) {
                    logerr("out of memory, TCP reassembly failed");
                    goto network_pkt_end;
                }
                tcpstate->reasm->seq_start = tcpstate->start;
                tcpstate->reasm->seq_bfb   = tcpstate->start;
            }
            if (options.allow_reset_tcpstate) {
                if (tcpstate->reasm_faults > options.reassemble_tcp_faultreset) {
                    if (dumptrace >= 3)
                        fprintf(stderr, "fault reset ");
                    tcpstate_reset(tcpstate, "too many reassembly faults");
                    tcpstate->reasm->seq_start = seq;
                    tcpstate->reasm->seq_bfb   = seq;
                    tcpstate->reasm_faults     = 0;
                }
                if (dumptrace >= 3)
                    fprintf(stderr, "reassemble\n");
                if (pcap_handle_tcp_segment(pkt, len, seq, tcpstate)) {
                    tcpstate->reasm_faults++;
                }
            } else {
                if (dumptrace >= 3)
                    fprintf(stderr, "reassemble\n");
                (void)pcap_handle_tcp_segment(pkt, len, seq, tcpstate);
            }
        } else if (tcpstate) {
            uint32_t seqdiff  = seq - tcpstate->start;
            tcpstate->currseq = seq;
            tcpstate->currlen = len;
            if (options.allow_reset_tcpstate && tcpstate->lastdns && seq > tcpstate->lastdns + 2) {
                /*
                 * seq received is beyond where we expect next DNS message
                 * to be, reset tcpstate and continue
                 */
                tcpstate->maxdiff = 0;
                tcpstate->dnslen  = 0;
                tcpstate->lastdns = seq;
            }
            if (dumptrace >= 3)
                fprintf(stderr, "diff=%08x; lastdns=%08x; ", seqdiff, tcpstate->lastdns);
            if (tcpstate->lastdns && seq == tcpstate->lastdns && len > 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+len+hdr\n");
                dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
                dnspkt                    = pkt + 2;
                if (dnslen > len - 2)
                    dnslen = len - 2;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->maxdiff = (uint32_t)len;
                tcpstate->lastdns = seq + 2 + tcpstate->dnslen;
            } else if (tcpstate->lastdns && seq == tcpstate->lastdns && len == 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+len\n");
                tcpstate->dnslen  = (pkt[0] << 8) | (pkt[1] << 0);
                tcpstate->maxdiff = (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts,
                    pkt_copy, olen, NULL, 0);
                _curr_tcpstate = 0;
                goto network_pkt_end;
            } else if (tcpstate->lastdns && ((seq == tcpstate->lastdns && len == 1) || seqdiff == 1)) {
                tcpstate_discard(tcpstate, NULL);
                goto network_pkt_end;
            } else if (tcpstate->lastdns && seq == tcpstate->lastdns + 2) {
                if (dumptrace >= 3)
                    fprintf(stderr, "+hdr\n");
                tcpstate->maxdiff = seqdiff + (uint32_t)len;
                dnslen            = tcpstate->dnslen;
                dnspkt            = pkt;
                if (dnslen == 0) /* we never received it */
                    dnslen = len;
                if (dnslen > len)
                    dnslen = len;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->lastdns = seq + tcpstate->dnslen;
            } else if (seqdiff == 0 && len > 2) {
                /* This is the first segment of the stream, and
             * contains the dnslen and dns header, so we can
             * filter on it. */
                if (dumptrace >= 3)
                    fprintf(stderr, "len+hdr\n");
                dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
                dnspkt                    = pkt + 2;
                if (dnslen > len - 2)
                    dnslen = len - 2;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->maxdiff = (uint32_t)len;
                tcpstate->lastdns = seq + 2 + tcpstate->dnslen;
            } else if (seqdiff == 0 && len == 2) {
                /* This is the first segment of the stream, but only
             * contains the dnslen. */
                if (dumptrace >= 3)
                    fprintf(stderr, "len\n");
                tcpstate->dnslen  = (pkt[0] << 8) | (pkt[1] << 0);
                tcpstate->maxdiff = (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts,
                    pkt_copy, olen, NULL, 0);
                _curr_tcpstate = 0;
                goto network_pkt_end;
            } else if ((seqdiff == 0 && len == 1) || seqdiff == 1) {
                /* shouldn't happen */
                tcpstate_discard(tcpstate, NULL);
                goto network_pkt_end;
            } else if (seqdiff == 2) {
                /* This is not the first segment, but it does contain
             * the first dns header, so we can filter on it. */
                if (dumptrace >= 3)
                    fprintf(stderr, "hdr\n");
                tcpstate->maxdiff = seqdiff + (uint32_t)len;
                dnslen            = tcpstate->dnslen;
                dnspkt            = pkt;
                if (dnslen == 0) /* we never received it */
                    dnslen = len;
                if (dnslen > len)
                    dnslen = len;
                flags |= DNSCAP_OUTPUT_ISDNS;
                tcpstate->lastdns = seq + tcpstate->dnslen;
            } else if (seqdiff > tcpstate->maxdiff + MAX_TCP_WINDOW) {
                /* This segment is outside the window. */
                if (dumptrace >= 3)
                    fprintf(stderr, "out of window\n");
                goto network_pkt_end;
            } else if (len == 0) {
                /* No payload (e.g., an ACK) */
                if (dumptrace >= 3)
                    fprintf(stderr, "empty\n");
                goto network_pkt_end;
            } else {
                /* non-first */
                if (dumptrace >= 3)
                    fprintf(stderr, "keep\n");
                if (tcpstate->maxdiff < seqdiff + (uint32_t)len)
                    tcpstate->maxdiff = seqdiff + (uint32_t)len;

                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts,
                    pkt_copy, olen, NULL, 0);
                _curr_tcpstate = 0;
                goto network_pkt_end;
            }
        } else {
            if (dumptrace >= 3)
                fprintf(stderr, "no state\n");
            /* There is no state for this stream.  Either we never saw
             * a SYN for this stream, or we have already decided to
             * discard this stream. */
            goto network_pkt_end;
        }
        break;
    }
    default:
        goto network_pkt_end;
    }

    for (m = 0; m < MAX_TCP_DNS_MSG; m++) {
        if (tcpstate && tcpstate->reasm) {
            if (!tcpstate->reasm->dnsmsg[m])
                continue;
            dnslen = tcpstate->reasm->dnsmsg[m]->dnslen;
            dnspkt = tcpstate->reasm->dnsmsg[m]->dnspkt;
            flags |= DNSCAP_OUTPUT_ISDNS;
            if (tcpstate->reasm->dnsmsg[m]->segments_seen > 1) {
                /* emulate dnslen in own packet */
                _curr_tcpstate = tcpstate;
                output(descr, from, to, proto, flags, sport, dport, ts,
                    pkt_copy, olen, NULL, 0);
                _curr_tcpstate = 0;
            }
        }

        /* Application. */
        if (!dnspkt) {
            tcpstate_discard(tcpstate, "no dns");
            goto network_pkt_end;
        }
        if (dnslen < sizeof dns) {
            tcpstate_discard(tcpstate, "too small");
            goto network_pkt_end;
        }
        memcpy(&dns, dnspkt, sizeof dns);

        /* Policy filtering. */
        if (dns.qr == 0 && dport == dns_port) {
            if ((dir_wanted & DIR_INITIATE) == 0) {
                tcpstate_discard(tcpstate, "unwanted dir=i");
                goto network_pkt_end;
            }
            initiator = from;
            responder = to;
            response  = FALSE;
        } else if (dns.qr != 0 && sport == dns_port) {
            if ((dir_wanted & DIR_RESPONSE) == 0) {
                tcpstate_discard(tcpstate, "unwanted dir=r");
                goto network_pkt_end;
            }
            initiator = to;
            responder = from;
            response  = TRUE;
        } else {
            tcpstate_discard(tcpstate, "unwanted direction/port");
            goto network_pkt_end;
        }
        if ((!EMPTY(initiators) && !ep_present(&initiators, initiator)) || (!EMPTY(responders) && !ep_present(&responders, responder))) {
            tcpstate_discard(tcpstate, "unwanted host");
            goto network_pkt_end;
        }
        if ((!EMPTY(not_initiators) && ep_present(&not_initiators, initiator)) || (!EMPTY(not_responders) && ep_present(&not_responders, responder))) {
            tcpstate_discard(tcpstate, "missing required host");
            goto network_pkt_end;
        }
        if (!(((msg_wanted & MSG_QUERY) != 0 && dns.opcode == LDNS_PACKET_QUERY) || ((msg_wanted & MSG_UPDATE) != 0 && dns.opcode == LDNS_PACKET_UPDATE) || ((msg_wanted & MSG_NOTIFY) != 0 && dns.opcode == LDNS_PACKET_NOTIFY))) {
            tcpstate_discard(tcpstate, "unwanted opcode");
            goto network_pkt_end;
        }
        if (response) {
            int match_tc    = (dns.tc != 0 && err_wanted & ERR_TRUNC);
            int match_rcode = err_wanted & (ERR_RCODE_BASE << dns.rcode);

            if (!match_tc && !match_rcode) {
                tcpstate_discard(tcpstate, "unwanted error code");
                goto network_pkt_end;
            }
            if (!EMPTY(drop_responders) && ep_present(&drop_responders, responder)) {
                tcpstate_discard(tcpstate, "dropped response due to -Y");
                goto network_pkt_end;
            }
        }
        if (!EMPTY(myregexes) || match_qtype || nmatch_qtype) {
            if (ldns_wire2pkt(&lpkt, dnspkt, dnslen) != LDNS_STATUS_OK) {
                /* DNS message may have padding, try get actual size */
                size_t dnslen2 = calcdnslen(dnspkt, dnslen);
                if (dnslen2 > 0 && dnslen2 < dnslen) {
                    if (ldns_wire2pkt(&lpkt, dnspkt, dnslen2) != LDNS_STATUS_OK) {
                        tcpstate_discard(tcpstate, "failed parse");
                        goto network_pkt_end;
                    }
                } else {
                    tcpstate_discard(tcpstate, "failed parse");
                    goto network_pkt_end;
                }
            }
        }
        if (match_qtype || nmatch_qtype) {
            ldns_rr_list* rrs = ldns_pkt_question(lpkt);
            if (!rrs) {
                tcpstate_discard(tcpstate, "failed to get list of questions");
                goto network_pkt_end;
            }
            /* Look at each RR in the section (or each QNAME in
               the question section). */
            size_t i, n;
            for (i = 0, n = ldns_rr_list_rr_count(rrs); i < n; i++) {
                ldns_rr* rr = ldns_rr_list_rr(rrs, i);
                if (!rr) {
                    tcpstate_discard(tcpstate, "failed to get question");
                    goto network_pkt_end;
                }

                if (match_qtype && ldns_rr_get_type(rr) != match_qtype) {
                    tcpstate_discard(tcpstate, "qtype not match");
                    goto network_pkt_end;
                } else if (nmatch_qtype && ldns_rr_get_type(rr) == nmatch_qtype) {
                    tcpstate_discard(tcpstate, "!qtype match");
                    goto network_pkt_end;
                }
            }
        }
        if (!EMPTY(myregexes)) {
            int          match, negmatch;
            ldns_buffer* buf = ldns_buffer_new(512);

            if (!buf) {
                fprintf(stderr, "%s: out of memory", ProgramName);
                exit(1);
            }

            match    = -1;
            negmatch = -1;
            /* Look at each section of the message:
                 question, answer, authority, additional */
            ldns_rr_list* rrs = ldns_pkt_all(lpkt);
            if (!rrs) {
                ldns_buffer_free(buf);
                tcpstate_discard(tcpstate, "failed to get list of RRs");
                goto network_pkt_end;
            }
            /* Look at each RR in the section (or each QNAME in
               the question section). */
            size_t i, n;
            for (i = 0, n = ldns_rr_list_rr_count(rrs); i < n; i++) {
                ldns_rr* rr = ldns_rr_list_rr(rrs, i);
                if (!rr) {
                    ldns_rr_list_free(rrs);
                    ldns_buffer_free(buf);
                    tcpstate_discard(tcpstate, "failed to get RR");
                    goto network_pkt_end;
                }

                ldns_buffer_clear(buf);
                if (ldns_rdf2buffer_str(buf, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
                    ldns_rr_list_free(rrs);
                    ldns_buffer_free(buf);
                    tcpstate_discard(tcpstate, "failed to get RR");
                    goto network_pkt_end;
                }

                myregex_ptr myregex;
                for (myregex = HEAD(myregexes);
                     myregex != NULL;
                     myregex = NEXT(myregex, link)) {
                    if (myregex->not ) {
                        if (negmatch < 0)
                            negmatch = 0;
                    } else {
                        if (match < 0)
                            match = 0;
                    }

                    if (regexec(&myregex->reg, (char*)ldns_buffer_begin(buf), 0, NULL, 0) == 0) {
                        if (myregex->not )
                            negmatch++;
                        else
                            match++;

                        if (dumptrace >= 2)
                            fprintf(stderr,
                                "; \"%s\" %s~ /%s/ %d %d\n",
                                (char*)ldns_buffer_begin(buf),
                                myregex->not ? "!" : "",
                                myregex->str,
                                match,
                                negmatch);
                    }
                }
            }
            ldns_rr_list_free(rrs);
            ldns_buffer_free(buf);

            /*
             * Fail if any negative matching or if no match, match can be -1 which
             * indicates that there are only negative matching
             */
            if (negmatch > 0 || match == 0) {
                tcpstate_discard(tcpstate, "failed regex match");
                goto network_pkt_end;
            }
        }

        /* Policy hiding. */
        if (end_hide != 0) {
            switch (from.af) {
            case AF_INET: {
                void *    init_addr, *resp_addr;
                uint16_t* init_port;

                if (dns.qr == 0) {
                    init_addr = (void*)&ip->ip_src;
                    resp_addr = (void*)&ip->ip_dst;
                    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
                } else {
                    init_addr = (void*)&ip->ip_dst;
                    resp_addr = (void*)&ip->ip_src;
                    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
                }

                if ((end_hide & END_INITIATOR) != 0) {
                    memcpy(init_addr, HIDE_INET, sizeof(struct in_addr));
                    *init_port = htons(HIDE_PORT);
                }
                if ((end_hide & END_RESPONDER) != 0)
                    memcpy(resp_addr, HIDE_INET, sizeof(struct in_addr));

                ip->ip_sum = 0;
                ip->ip_sum = ~in_checksum((u_char*)ip, sizeof *ip);
                if (udp)
                    udp->uh_sum = 0U;
                break;
            }
            case AF_INET6: {
                void *    init_addr, *resp_addr;
                uint16_t* init_port;

                if (dns.qr == 0) {
                    init_addr = (void*)&ipv6->ip6_src;
                    resp_addr = (void*)&ipv6->ip6_dst;
                    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
                } else {
                    init_addr = (void*)&ipv6->ip6_dst;
                    resp_addr = (void*)&ipv6->ip6_src;
                    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
                }

                if ((end_hide & END_INITIATOR) != 0) {
                    memcpy(init_addr, HIDE_INET6, sizeof(struct in6_addr));
                    *init_port = htons(HIDE_PORT);
                }
                if ((end_hide & END_RESPONDER) != 0)
                    memcpy(resp_addr, HIDE_INET6, sizeof(struct in6_addr));

                if (udp)
                    udp->uh_sum = 0U;
                break;
            }
            default:
                abort();
            }
        }
        _curr_tcpstate = tcpstate;
        output(descr, from, to, proto, flags, sport, dport, ts,
            pkt_copy, olen, dnspkt, dnslen);
        _curr_tcpstate = 0;

        if (tcpstate && tcpstate->reasm) {
            free(tcpstate->reasm->dnsmsg[m]);
            tcpstate->reasm->dnsmsg[m] = 0;
            tcpstate->reasm->dnsmsgs--;
        } else
            break;
    }

network_pkt_end:
    network_ip   = 0;
    network_ipv6 = 0;
    if (lpkt) {
        ldns_pkt_free(lpkt);
    }
}

uint16_t in_checksum(const u_char* ptr, size_t len)
{
    unsigned sum = 0, top;

    /* Main body. */
    while (len >= 2) {
        sum += *(const uint16_t*)ptr;
        ptr += 2;
        len -= 2;
    }

    /* Leftover octet? */
    if (len != 0)
        sum += *ptr;

    /* Leftover carries? */
    while ((top = (sum >> 16)) != 0)
        sum = ((uint16_t)sum) + top;

    /* Caller should ~ this result. */
    return ((uint16_t)sum);
}

static size_t calcrr(int q, const u_char* p, size_t l, size_t t)
{
    while (l < t) {
        if ((p[l] & 0xc0) == 0xc0) {
            l += 2;
        } else if (p[l] & 0xc0) {
            l += 1;
        } else if (p[l]) {
            l += p[l];
        } else {
            break;
        }
    }
    l += 4; /* type + class */
    if (q)
        return l;
    l += 6; /* ttl + rdlength */
    if (l < t) {
        l += (p[l - 2] << 8) + p[l - 1]; /* rdata */
    }
    return l;
}

size_t calcdnslen(const u_char* dnspkt, size_t dnslen)
{
    HEADER dns;
    size_t n, len;

    if (dnslen > 65535 || dnslen < sizeof(dns)) {
        return 0;
    }
    memcpy(&dns, dnspkt, sizeof dns);
    len = sizeof(dns);

    for (n = 0; len < dnslen && n < dns.qdcount; n++) {
        len = calcrr(1, dnspkt, len, dnslen);
    }
    for (n = 0; len < dnslen && n < dns.ancount; n++) {
        len = calcrr(0, dnspkt, len, dnslen);
    }
    for (n = 0; len < dnslen && n < dns.nscount; n++) {
        len = calcrr(0, dnspkt, len, dnslen);
    }
    for (n = 0; len < dnslen && n < dns.arcount; n++) {
        len = calcrr(0, dnspkt, len, dnslen);
    }
    if (len < dnslen)
        return len;
    return dnslen;
}
