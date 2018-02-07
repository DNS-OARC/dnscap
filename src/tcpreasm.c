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

#include "tcpreasm.h"
#include "log.h"
#include "network.h"

#include <stdlib.h>

#define dfprintf(a, b...)      \
    if (dumptrace >= 3) {      \
        fprintf(stderr, b);    \
        fprintf(stderr, "\n"); \
    }
#define dsyslogf(a, b...) logerr(b)
#define nptohs(p) ((((uint8_t*)(p))[0] << 8) | ((uint8_t*)(p))[1])

#define BFB_BUF_SIZE (0xffff + 0xffff + 2 + 2)

/*
 * Originally from DSC:
 *
 * TCP Reassembly.
 *
 * When we see a SYN, we allocate a new tcpstate for the connection, and
 * establish the initial sequence number of the first dns message (seq_start)
 * on the connection.  We assume that no other segment can arrive before the
 * SYN (if one does, it is discarded, and if is not repeated the message it
 * belongs to can never be completely reassembled).
 *
 * Then, for each segment that arrives on the connection:
 * - If it's the first segment of a message (containing the 2-byte message
 *   length), we allocate a msgbuf, and check for any held segments that might
 *   belong to it.
 * - If the first byte of the segment belongs to any msgbuf, we fill
 *   in the holes of that message.  If the message has no more holes, we
 *   handle the complete dns message.  If the tail of the segment was longer
 *   than the hole, we recurse on the tail.
 * - Otherwise, if the segment could be within the tcp window, we hold onto it
 *   pending the creation of a matching msgbuf.
 *
 * This algorithm handles segments that arrive out of order, duplicated or
 * overlapping (including segments from different dns messages arriving out of
 * order), and dns messages that do not necessarily start on segment
 * boundaries.
 *
 */

static int dns_protocol_handler(tcpreasm_t* t, u_char* segment, uint16_t dnslen, uint32_t seq)
{
    int m;

#if HAVE_NS_INITPARSE
    if (options.reassemble_tcp_bfbparsedns) {
        int    s;
        ns_msg msg;
        size_t at, len;

        if (!t->bfb_buf && !(t->bfb_buf = malloc(BFB_BUF_SIZE))) {
            dfprintf(1, "dns_protocol_handler: no memory for bfb_buf");
            return 1;
        }

        /* if this is the first segment, add it to the processing buffer
           and move up to next wanted segment */
        if (seq == t->seq_bfb + 2) {
            dfprintf(1, "dns_protocol_handler: first bfb_seg: seq = %u, len = %d", seq, dnslen);
            if ((BFB_BUF_SIZE - t->bfb_at) < (dnslen + 2)) {
                dfprintf(1, "dns_protocol_handler: out of space in bfb_buf");
                return 1;
            }

            t->bfb_buf[t->bfb_at++] = dnslen >> 8;
            t->bfb_buf[t->bfb_at++] = dnslen & 0xff;
            memcpy(&t->bfb_buf[t->bfb_at], segment, dnslen);
            t->bfb_at += dnslen;
            t->seq_bfb += 2 + dnslen;
        } else {
            /* add segment for later processing */
            dfprintf(1, "dns_protocol_handler: add bfb_seg: seq = %u, len = %d", seq, dnslen);
            for (s = 0;; s++) {
                if (s >= MAX_TCP_SEGS) {
                    dfprintf(1, "dns_protocol_handler: out of bfbsegs");
                    return 1;
                }
                if (t->bfb_seg[s])
                    continue;
                t->bfb_seg[s]      = calloc(1, sizeof(tcp_segbuf_t) + dnslen);
                t->bfb_seg[s]->seq = seq;
                t->bfb_seg[s]->len = dnslen;
                memcpy(t->bfb_seg[s]->buf, segment, dnslen);
                dfprintf(1, "dns_protocol_handler: new bfbseg %d: seq = %u, len = %d",
                    s, t->bfb_seg[s]->seq, t->bfb_seg[s]->len);
                break;
            }
            return 0;
        }

        for (;;) {
            /* process the buffer, extract dnslen and try and parse */
            for (at = 0, len = t->bfb_at;;) {
                dfprintf(1, "dns_protocol_handler: processing at = %lu, len = %lu", at, len);
                if (len < 2) {
                    dfprintf(1, "dns_protocol_handler: bfb need more for dnslen");
                    break;
                }
                dnslen = nptohs(&t->bfb_buf[at]) & 0xffff;
                if (dnslen > 11) {
                    /* 12 bytes minimum DNS header, other lengths should be invalid */
                    if (len < dnslen + 2) {
                        dfprintf(1, "dns_protocol_handler: bfb need %lu more", dnslen - len);
                        break;
                    }

                    if (!ns_initparse(&t->bfb_buf[at + 2], dnslen, &msg)) {
                        dfprintf(1, "dns_protocol_handler: dns at %lu len %u", at + 2, dnslen);

                        for (m = 0; t->dnsmsg[m];) {
                            if (++m >= MAX_TCP_DNS_MSG) {
                                dfprintf(1, "dns_protocol_handler: %s", "out of dnsmsgs");
                                return 1;
                            }
                        }
                        if (!(t->dnsmsg[m] = calloc(1, sizeof(tcpdnsmsg_t) + dnslen))) {
                            dsyslogf(LOG_ERR, "out of memory for dnsmsg (%d)", dnslen);
                            return 1;
                        }
                        t->dnsmsgs++;
                        t->dnsmsg[m]->dnslen = dnslen;
                        memcpy(t->dnsmsg[m]->dnspkt, &t->bfb_buf[at + 2], dnslen);
                        dfprintf(1, "dns_protocol_handler: new dnsmsg %d: dnslen = %d", m, dnslen);

                        at += 2 + dnslen;
                        len -= 2 + dnslen;
                        continue;
                    }
                    if (errno == EMSGSIZE) {
                        size_t l = calcdnslen(&t->bfb_buf[at + 2], dnslen);
                        if (l > 0 && l < dnslen && !ns_initparse(&t->bfb_buf[at + 2], l, &msg)) {
                            dfprintf(1, "dns_protocol_handler: dns at %lu len %u (real len %lu)", at + 2, dnslen, l);

                            for (m = 0; t->dnsmsg[m];) {
                                if (++m >= MAX_TCP_DNS_MSG) {
                                    dfprintf(1, "dns_protocol_handler: %s", "out of dnsmsgs");
                                    return 1;
                                }
                            }
                            if (!(t->dnsmsg[m] = calloc(1, sizeof(tcpdnsmsg_t) + dnslen))) {
                                dsyslogf(LOG_ERR, "out of memory for dnsmsg (%d)", dnslen);
                                return 1;
                            }
                            t->dnsmsgs++;
                            t->dnsmsg[m]->dnslen = dnslen;
                            memcpy(t->dnsmsg[m]->dnspkt, &t->bfb_buf[at + 2], dnslen);
                            dfprintf(1, "dns_protocol_handler: new dnsmsg %d: dnslen = %d", m, dnslen);

                            at += 2 + dnslen;
                            len -= 2 + dnslen;
                            continue;
                        }
                    }
                }
                dfprintf(1, "dns_protocol_handler: bfb dns parse failed at %lu", at);
                at += 2;
                len -= 2;
            }

            /* check for leftovers in the buffer */
            if (!len) {
                dfprintf(1, "dns_protocol_handler: bfb all buf parsed, reset at");
                t->bfb_at = 0;
            } else if (len && at) {
                dfprintf(1, "dns_protocol_handler: bfb move %lu len %lu", at, len);
                memmove(t->bfb_buf, &t->bfb_buf[at], len);
                t->bfb_at = len;
            }

            dfprintf(1, "dns_protocol_handler: bfb fill at %lu", t->bfb_at);
            /* see if we can fill the buffer */
            for (s = 0;; s++) {
                if (s >= MAX_TCP_SEGS) {
                    dfprintf(1, "dns_protocol_handler: bfb need next seg");
                    return 0;
                }
                if (!t->bfb_seg[s])
                    continue;

                if (t->bfb_seg[s]->seq == t->seq_bfb + 2) {
                    tcp_segbuf_t* seg = t->bfb_seg[s];
                    dfprintf(1, "dns_protocol_handler: next bfb_seg %d: seq = %u, len = %d", s, seg->seq, seg->len);
                    if ((BFB_BUF_SIZE - t->bfb_at) < (seg->len + 2)) {
                        dfprintf(1, "dns_protocol_handler: out of space in bfb_buf");
                        return 1;
                    }
                    t->bfb_seg[s]           = 0;
                    t->bfb_buf[t->bfb_at++] = seg->len >> 8;
                    t->bfb_buf[t->bfb_at++] = seg->len & 0xff;
                    memcpy(&t->bfb_buf[t->bfb_at], seg->buf, seg->len);
                    t->bfb_at += seg->len;
                    t->seq_bfb += 2 + seg->len;
                    free(seg);
                    break;
                }
            }
            len = t->bfb_at;
        }
        return 0;
    }
#endif

    for (m = 0; t->dnsmsg[m];) {
        if (++m >= MAX_TCP_DNS_MSG) {
            dfprintf(1, "dns_protocol_handler: %s", "out of dnsmsgs");
            return 1;
        }
    }
    t->dnsmsg[m] = calloc(1, sizeof(tcpdnsmsg_t) + dnslen);
    if (NULL == t->dnsmsg[m]) {
        dsyslogf(LOG_ERR, "out of memory for dnsmsg (%d)", dnslen);
        return 1;
    }
    t->dnsmsgs++;
    t->dnsmsg[m]->segments_seen = t->segments_seen;
    t->dnsmsg[m]->dnslen        = dnslen;
    memcpy(t->dnsmsg[m]->dnspkt, segment, dnslen);
    dfprintf(1, "dns_protocol_handler: new dnsmsg %d: dnslen = %d", m, dnslen);
    t->segments_seen = 0;
    return 0;
}

int pcap_handle_tcp_segment(u_char* segment, int len, uint32_t seq, tcpstate_ptr _tcpstate)
{
    int         i, m, s, ret;
    uint16_t    dnslen;
    int         segoff, seglen;
    tcpreasm_t* tcpstate = _tcpstate->reasm;

    dfprintf(1, "pcap_handle_tcp_segment: seq=%u, len=%d", seq, len);

    if (len <= 0) /* there is no more payload */
        return 0;

    tcpstate->segments_seen++;

    if (seq - tcpstate->seq_start < 2) {
        /* this segment contains all or part of the 2-byte DNS length field */
        uint32_t o = seq - tcpstate->seq_start;
        int      l = (len > 1 && o == 0) ? 2 : 1;
        dfprintf(1, "pcap_handle_tcp_segment: copying %d bytes to dnslen_buf[%d]", l, o);
        memcpy(&tcpstate->dnslen_buf[o], segment, l);
        if (l == 2)
            tcpstate->dnslen_bytes_seen_mask = 3;
        else
            tcpstate->dnslen_bytes_seen_mask |= (1 << o);
        len -= l;
        segment += l;
        seq += l;
    }

    if (3 == tcpstate->dnslen_bytes_seen_mask) {
        /* We have the dnslen stored now */
        dnslen = nptohs(tcpstate->dnslen_buf) & 0xffff;
        /*
         * Next we poison the mask to indicate we are in to the message body.
         * If one doesn't remember we're past the then,
         * one loops forever getting more msgbufs rather than filling
         * in the contents of THIS message.
         *
         * We need to later reset that mask when we process the message
         * (method: tcpstate->dnslen_bytes_seen_mask = 0).
         */
        tcpstate->dnslen_bytes_seen_mask = 7;
        tcpstate->seq_start += sizeof(uint16_t) + dnslen;
        dfprintf(1, "pcap_handle_tcp_segment: first segment; dnslen = %d", dnslen);
        if (len >= dnslen) {
            /* this segment contains a complete message - avoid the reassembly
             * buffer and just handle the message immediately */
            ret = dns_protocol_handler(tcpstate, segment, dnslen, seq);

            tcpstate->dnslen_bytes_seen_mask = 0; /* go back for another message in this tcp connection */
            /* handle the trailing part of the segment? */
            if (len > dnslen) {
                dfprintf(1, "pcap_handle_tcp_segment: %s", "segment tail");
                ret |= pcap_handle_tcp_segment(segment + dnslen, len - dnslen, seq + dnslen, _tcpstate);
            }
            return ret;
        }
        /*
         * At this point we KNOW we have an incomplete message and need to do reassembly.
         * i.e.:  assert(len < dnslen);
         */
        dfprintf(2, "pcap_handle_tcp_segment: %s", "buffering segment");
        /* allocate a msgbuf for reassembly */
        for (m = 0; tcpstate->msgbuf[m];) {
            if (++m >= MAX_TCP_MSGS) {
                dfprintf(1, "pcap_handle_tcp_segment: %s", "out of msgbufs");
                return 1;
            }
        }
        tcpstate->msgbuf[m] = calloc(1, sizeof(tcp_msgbuf_t) + dnslen);
        if (NULL == tcpstate->msgbuf[m]) {
            dsyslogf(LOG_ERR, "out of memory for tcp_msgbuf (%d)", dnslen);
            return 1;
        }
        tcpstate->msgbufs++;
        tcpstate->msgbuf[m]->seq           = seq;
        tcpstate->msgbuf[m]->dnslen        = dnslen;
        tcpstate->msgbuf[m]->holes         = 1;
        tcpstate->msgbuf[m]->hole[0].start = len;
        tcpstate->msgbuf[m]->hole[0].len   = dnslen - len;
        dfprintf(1,
            "pcap_handle_tcp_segment: new msgbuf %d: seq = %u, dnslen = %d, hole start = %d, hole len = %d", m,
            tcpstate->msgbuf[m]->seq, tcpstate->msgbuf[m]->dnslen, tcpstate->msgbuf[m]->hole[0].start,
            tcpstate->msgbuf[m]->hole[0].len);
        /* copy segment to appropriate location in reassembly buffer */
        memcpy(tcpstate->msgbuf[m]->buf, segment, len);

        /* Now that we know the length of this message, we must check any held
         * segments to see if they belong to it. */
        ret = 0;
        for (s = 0; s < MAX_TCP_SEGS; s++) {
            if (!tcpstate->segbuf[s])
                continue;
            /* TODO: seq >= 0 */
            if (tcpstate->segbuf[s]->seq - seq > 0 && tcpstate->segbuf[s]->seq - seq < dnslen) {
                tcp_segbuf_t* segbuf = tcpstate->segbuf[s];
                tcpstate->segbuf[s]  = NULL;
                dfprintf(1, "pcap_handle_tcp_segment: %s", "message reassembled");
                ret |= pcap_handle_tcp_segment(segbuf->buf, segbuf->len, segbuf->seq, _tcpstate);
                /*
                 * Note that our recursion will also cover any tail messages (I hope).
                 * Thus we do not need to do so here and can return.
                 */
                free(segbuf);
            }
        }
        return ret;
    }

    /*
     * Welcome to reassembly-land.
     */
    /* find the message to which the first byte of this segment belongs */
    for (m = 0;; m++) {
        if (m >= MAX_TCP_MSGS) {
            /* seg does not match any msgbuf; just hold on to it. */
            dfprintf(1, "pcap_handle_tcp_segment: %s", "seg does not match any msgbuf");

            if (seq - tcpstate->seq_start > MAX_TCP_WINDOW_SIZE) {
                dfprintf(1, "pcap_handle_tcp_segment: %s %u %u", "seg is outside window; discarding", seq, tcpstate->seq_start);
                return 1;
            }
            for (s = 0;; s++) {
                if (s >= MAX_TCP_SEGS) {
                    dfprintf(1, "pcap_handle_tcp_segment: %s", "out of segbufs");
                    return 1;
                }
                if (tcpstate->segbuf[s])
                    continue;
                tcpstate->segbuf[s]      = calloc(1, sizeof(tcp_segbuf_t) + len);
                tcpstate->segbuf[s]->seq = seq;
                tcpstate->segbuf[s]->len = len;
                memcpy(tcpstate->segbuf[s]->buf, segment, len);
                dfprintf(1, "pcap_handle_tcp_segment: new segbuf %d: seq = %u, len = %d",
                    s, tcpstate->segbuf[s]->seq, tcpstate->segbuf[s]->len);
                return 0;
            }
        }
        if (!tcpstate->msgbuf[m])
            continue;
        segoff = seq - tcpstate->msgbuf[m]->seq;
        if (segoff >= 0 && segoff < tcpstate->msgbuf[m]->dnslen) {
            /* segment starts in this msgbuf */
            dfprintf(1, "pcap_handle_tcp_segment: seg matches msg %d: seq = %u, dnslen = %d",
                m, tcpstate->msgbuf[m]->seq, tcpstate->msgbuf[m]->dnslen);
            if (segoff + len > tcpstate->msgbuf[m]->dnslen) {
                /* segment would overflow msgbuf */
                seglen = tcpstate->msgbuf[m]->dnslen - segoff;
                dfprintf(1, "pcap_handle_tcp_segment: using partial segment %d", seglen);
            } else {
                seglen = len;
            }
            break;
        }
    }

    /* Reassembly algorithm adapted from RFC 815. */
    for (i = 0; i < MAX_TCP_HOLES; i++) {
        tcphole_t* newhole;
        uint16_t   hole_start, hole_len;
        if (tcpstate->msgbuf[m]->hole[i].len == 0)
            continue; /* hole descriptor is not in use */
        hole_start = tcpstate->msgbuf[m]->hole[i].start;
        hole_len   = tcpstate->msgbuf[m]->hole[i].len;
        if (segoff >= hole_start + hole_len)
            continue; /* segment is totally after hole */
        if (segoff + seglen <= hole_start)
            continue; /* segment is totally before hole */
        /* The segment overlaps this hole.  Delete the hole. */
        dfprintf(1, "pcap_handle_tcp_segment: overlaping hole %d: %d %d", i, hole_start, hole_len);
        tcpstate->msgbuf[m]->hole[i].len = 0;
        tcpstate->msgbuf[m]->holes--;
        if (segoff + seglen < hole_start + hole_len) {
            /* create a new hole after the segment (common case) */
            newhole        = &tcpstate->msgbuf[m]->hole[i]; /* hole[i] is guaranteed free */
            newhole->start = segoff + seglen;
            newhole->len   = (hole_start + hole_len) - newhole->start;
            tcpstate->msgbuf[m]->holes++;
            dfprintf(1, "pcap_handle_tcp_segment: new post-hole %d: %d %d", i, newhole->start, newhole->len);
        }
        if (segoff > hole_start) {
            /* create a new hole before the segment */
            int j;
            for (j = 0;; j++) {
                if (j == MAX_TCP_HOLES) {
                    dfprintf(1, "pcap_handle_tcp_segment: %s", "out of hole descriptors");
                    return 1;
                }
                if (tcpstate->msgbuf[m]->hole[j].len == 0) {
                    newhole = &tcpstate->msgbuf[m]->hole[j];
                    break;
                }
            }
            tcpstate->msgbuf[m]->holes++;
            newhole->start = hole_start;
            newhole->len   = segoff - hole_start;
            dfprintf(1, "pcap_handle_tcp_segment: new pre-hole %d: %d %d", j, newhole->start, newhole->len);
        }
        if (segoff >= hole_start && (hole_len == 0 || segoff + seglen < hole_start + hole_len)) {
            /* The segment does not extend past hole boundaries; there is
             * no need to look for other matching holes. */
            break;
        }
    }

    /* copy payload to appropriate location in reassembly buffer */
    memcpy(&tcpstate->msgbuf[m]->buf[segoff], segment, seglen);

    dfprintf(1, "pcap_handle_tcp_segment: holes remaining: %d", tcpstate->msgbuf[m]->holes);

    ret = 0;
    if (tcpstate->msgbuf[m]->holes == 0) {
        /* We now have a completely reassembled dns message */
        dfprintf(2, "pcap_handle_tcp_segment: %s", "reassembly to dns_protocol_handler");
        ret |= dns_protocol_handler(tcpstate, tcpstate->msgbuf[m]->buf, tcpstate->msgbuf[m]->dnslen, tcpstate->msgbuf[m]->seq);
        tcpstate->dnslen_bytes_seen_mask = 0; /* go back for another message in this tcp connection */
        free(tcpstate->msgbuf[m]);
        tcpstate->msgbuf[m] = NULL;
        tcpstate->msgbufs--;
    }

    if (seglen < len) {
        dfprintf(1, "pcap_handle_tcp_segment: %s", "segment tail after reassembly");
        ret |= pcap_handle_tcp_segment(segment + seglen, len - seglen, seq + seglen, _tcpstate);
    } else {
        dfprintf(1, "pcap_handle_tcp_segment: %s", "nothing more after reassembly");
    }

    return ret;
}

void tcpreasm_free(tcpreasm_t* tcpreasm)
{
    int i;

    if (tcpreasm) {
        for (i = 0; i < MAX_TCP_MSGS; i++) {
            if (tcpreasm->msgbuf[i]) {
                free(tcpreasm->msgbuf[i]);
            }
        }
        for (i = 0; i < MAX_TCP_SEGS; i++) {
            if (tcpreasm->segbuf[i]) {
                free(tcpreasm->segbuf[i]);
            }
            if (tcpreasm->bfb_seg[i]) {
                free(tcpreasm->bfb_seg[i]);
            }
        }
        for (i = 0; i < MAX_TCP_DNS_MSG; i++) {
            if (tcpreasm->dnsmsg[i]) {
                free(tcpreasm->dnsmsg[i]);
            }
        }
        free(tcpreasm->bfb_buf);
        free(tcpreasm);
    }
}

void tcpreasm_reset(tcpreasm_t* tcpreasm)
{
    int i;

    if (tcpreasm) {
        for (i = 0; i < MAX_TCP_MSGS; i++) {
            if (tcpreasm->msgbuf[i]) {
                free(tcpreasm->msgbuf[i]);
            }
        }
        for (i = 0; i < MAX_TCP_SEGS; i++) {
            if (tcpreasm->segbuf[i]) {
                free(tcpreasm->segbuf[i]);
            }
            if (tcpreasm->bfb_seg[i]) {
                free(tcpreasm->bfb_seg[i]);
            }
        }
        for (i = 0; i < MAX_TCP_DNS_MSG; i++) {
            if (tcpreasm->dnsmsg[i]) {
                free(tcpreasm->dnsmsg[i]);
            }
        }
        memset(tcpreasm, 0, sizeof(tcpreasm_t));
    }
}
