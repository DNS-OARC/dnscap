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

#include "config.h"

#include "tcpstate.h"
#include "iaddr.h"
#include "log.h"
#include "tcpreasm.h"

#define MAX_TCP_IDLE_TIME 600
#define MAX_TCP_IDLE_COUNT (4096 * 128)
#define TCP_GC_TIME 60
#define GC_COUNTER_MAX 100

void tcpstate_discard_from_list(tcpstate_list *list, tcpstate_ptr tcpstate, const char* msg);
void tcpstate_discard(tcpstate_ptr tcpstate, const char* msg);

void tcpstate_gc (time_t t)
{
    static time_t next_gc = 0;
    tcpstate_ptr  tcpstate;
    tcpstate_list *tcpstates_p;

    if (tcpstates_hash == NULL) return;
#ifndef __clang_analyzer__
    /* disabled during scan-build due to false-positives */
    if (t >= next_gc || tcpstate_count > MAX_TCP_IDLE_COUNT) {
        int i;
        for (i=0; i < tcpstates_hash->num_bins; i++) {
            tcpstates_p = &tcpstates_hash->bins[i];
            while ((tcpstate = TAIL(*tcpstates_p)) && (tcpstate->last_use < (t - MAX_TCP_IDLE_TIME))) {
                tcpstate_discard_from_list (tcpstates_p, tcpstate, "gc stale");
            }
        }
        next_gc = t + TCP_GC_TIME;
    }
#endif
}

int tcpstate_hash_func (tcpstate_hash_t *h, iaddr from, iaddr to, unsigned sport, unsigned dport) {
    uint32_t hash_val = 0;
    uint16_t *p;

    if (h == NULL) return (hash_val);
    if (from.af == AF_INET) {
        p = (uint16_t *) &from.u.a4.s_addr;
        hash_val += p[0];
        hash_val += p[1];
    } else if (from.af == AF_INET6) {
        p = from.u.a6.s6_addr16;
        hash_val += p[0]; hash_val += p[1]; hash_val += p[2]; hash_val += p[3];
        hash_val += p[4]; hash_val += p[5]; hash_val += p[6]; hash_val += p[7];
    }
    if (to.af == AF_INET) {
        p = (uint16_t *) &to.u.a4.s_addr;
        hash_val += p[0];
        hash_val += p[1];
    } else if (to.af == AF_INET6) {
        p = to.u.a6.s6_addr16;
        hash_val += p[0]; hash_val += p[1]; hash_val += p[2]; hash_val += p[3];
        hash_val += p[4]; hash_val += p[5]; hash_val += p[6]; hash_val += p[7];
    }
    hash_val += sport;
    hash_val += dport;
    return (hash_val % h->num_bins);
}

tcpstate_hash_t *tcpstate_hash_init (int nbits) {
    int i;
    tcpstate_hash_t *h = calloc (1, sizeof (tcpstate_hash_t));
    if (h == NULL) return (NULL);

    h->num_bins = 1 << nbits;
    h->bins = calloc (h->num_bins, sizeof (tcpstate_list));
    if (h->bins == NULL) {
        free (h);
        return (NULL);
    }

    for (i=0; i < h->num_bins; i++)
        INIT_LIST (h->bins[i]);

    h->hash_func = tcpstate_hash_func;
    return (h);
}

void tcpstate_hash_free (tcpstate_hash_t *hash)
{
    int i;
    if (hash == NULL) return;
    for (i=0; i < hash->num_bins; i++)
        INIT_LIST (hash->bins[i]);
    free (hash->bins);
    free (hash);
    return;
}

tcpstate_list *tcpstate_hash_get (tcpstate_hash_t *h, iaddr from, iaddr to, unsigned sport, unsigned dport) {
    int hash_val;
    if ((h == NULL) || (h->hash_func == NULL)) return (NULL);
    hash_val = h->hash_func (h, from, to, sport, dport);
    return (&h->bins[hash_val]);
}

tcpstate_ptr tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t)
{
    tcpstate_list *tcpstates_p;
    tcpstate_ptr  tcpstate;
    static int gc_counter = 0;

    tcpstates_p = tcpstate_hash_get (tcpstates_hash, from, to, sport, dport);
    if (tcpstates_p == NULL) return (NULL);

    for (tcpstate = HEAD(*tcpstates_p); tcpstate != NULL; tcpstate = NEXT(tcpstate, link)) {
        if (ia_equal(tcpstate->saddr, from) && ia_equal(tcpstate->daddr, to) && tcpstate->sport == sport && tcpstate->dport == dport)
            break;
    }
    if (tcpstate != NULL) {
        tcpstate->last_use = t;
        if (tcpstate != HEAD(*tcpstates_p)) {
            /* move to beginning of list */
            UNLINK(*tcpstates_p, tcpstate, link);
            PREPEND(*tcpstates_p, tcpstate, link);
        }
    }
    
    if (gc_counter >= GC_COUNTER_MAX) {
        tcpstate_gc(t);
        gc_counter = 0;
    } else {
        gc_counter++;
    }

    return tcpstate;
}

tcpstate_ptr _curr_tcpstate = 0;

tcpstate_ptr tcpstate_getcurr(void)
{
    return _curr_tcpstate;
}

tcpstate_ptr tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport)
{
    tcpstate_list *tcpstates_p;
    tcpstates_p = tcpstate_hash_get(tcpstates_hash, from, to, sport, dport);
    assert(tcpstates_p != NULL);

    tcpstate_ptr tcpstate = calloc(1, sizeof *tcpstate);
    if (tcpstate == NULL) {
        /* Out of memory; recycle the least recently used */
        logerr("warning: out of memory, "
               "discarding some TCP state early");
        tcpstate = TAIL(*tcpstates_p);
        assert(tcpstate != NULL);
        UNLINK(*tcpstates_p, tcpstate, link);
    } else {
        tcpstate_count++;
    }
    tcpstate->saddr = from;
    tcpstate->daddr = to;
    tcpstate->sport = sport;
    tcpstate->dport = dport;
    INIT_LINK(tcpstate, link);
    PREPEND(*tcpstates_p, tcpstate, link);
    return tcpstate;
}

/* Discard this packet.  If it's part of TCP stream, all subsequent pkts on
 * the same tcp stream will also be discarded. */

void tcpstate_discard_from_list(tcpstate_list *list, tcpstate_ptr tcpstate, const char* msg)
{
    if ((list == NULL) || (tcpstate == NULL)) return;
    UNLINK(*list, tcpstate, link);
    if (tcpstate->reasm) {
        tcpreasm_free(tcpstate->reasm);
    }
    free(tcpstate);
    if (_curr_tcpstate == tcpstate) {
        _curr_tcpstate = 0;
    }
    tcpstate_count--;
    return;
}

void tcpstate_discard(tcpstate_ptr tcpstate, const char* msg)
{
    if (dumptrace >= 3 && msg)
        fprintf(stderr, "discarding packet: %s\n", msg);
    if (tcpstate) {
        tcpstate_list *tcpstates_p;
        tcpstates_p = tcpstate_hash_get(tcpstates_hash, tcpstate->saddr, tcpstate->daddr, tcpstate->sport, tcpstate->dport);
        tcpstate_discard_from_list(tcpstates_p, tcpstate, msg);
    }
}

void tcpstate_reset(tcpstate_ptr tcpstate, const char* msg)
{
    if (options.allow_reset_tcpstate && tcpstate) {
        if (dumptrace >= 3 && msg)
            fprintf(stderr, "resetting tcpstate: %s\n", msg);

        tcpstate->start   = tcpstate->currseq;
        tcpstate->maxdiff = 0;
        tcpstate->dnslen  = 0;
        tcpstate->lastdns = tcpstate->currseq + tcpstate->currlen;

        if (tcpstate->reasm) {
            tcpreasm_reset(tcpstate->reasm);
            tcpstate->reasm->seq_start = tcpstate->start;
        }
    }
}
