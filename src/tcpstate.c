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
#define MAX_TCP_IDLE_COUNT (4096 * 512)
#define TCP_GC_TIME 60
#define GC_COUNTER_MAX 100

void tcpstate_discard_from_list(tcpstate_list *list, tcpstate_ptr tcpstate, const char* msg);

unsigned int
tcpstate_hash (const void *key)
{
    const tcpstate_ptr tcpstate = (const tcpstate_ptr)key;
    uint16_t *p;
    unsigned int hash_val = 0;

    if (tcpstate->saddr.af == AF_INET) {
        p = (uint16_t *) &tcpstate->saddr.u.a4.s_addr;
        hash_val += p[0]; hash_val += p[1];
    } else if (tcpstate->saddr.af == AF_INET6) {
        p = tcpstate->saddr.u.a6.s6_addr16;
        hash_val += p[0]; hash_val += p[1]; hash_val += p[2]; hash_val += p[3];
        hash_val += p[4]; hash_val += p[5]; hash_val += p[6]; hash_val += p[7];
    }

    if (tcpstate->daddr.af == AF_INET) {
        p = (uint16_t *) &tcpstate->daddr.u.a4.s_addr;
        hash_val += p[0]; hash_val += p[1];
    } else if (tcpstate->daddr.af == AF_INET6) {
        p = tcpstate->daddr.u.a6.s6_addr16;
        hash_val += p[0]; hash_val += p[1]; hash_val += p[2]; hash_val += p[3];
        hash_val += p[4]; hash_val += p[5]; hash_val += p[6]; hash_val += p[7];
    }

    hash_val += tcpstate->sport;
    hash_val += tcpstate->dport;
    return (hash_val);
}

int
tcpstate_cmp (const void* _a, const void* _b)
{
    /* There will only be a single LIST() of tcpstates in each hash table
     * slot.  Therefore, this cmp function will always match and return 0
     */
    return (0);
}

void tcpstate_gc (time_t t) {
    static time_t next_gc = 0;
    tcpstate_ptr  tcpstate;
    int i;

    if (tcpstate_hashtbl == NULL) return;
    if ((t < next_gc) && (tcpstate_count < MAX_TCP_IDLE_COUNT)) return;

    for (i=0; i < tcpstate_hashtbl->modulus; i++) {
        hashitem *hi = tcpstate_hashtbl->items[i];
        if ((hi != NULL) && (hi->data != NULL)) {
            tcpstate_list *tcpstates_p = (tcpstate_list *)hi->data;
            while ((tcpstate = TAIL(*tcpstates_p)) && (tcpstate->last_use < (t - MAX_TCP_IDLE_TIME))) {
                tcpstate_discard_from_list (tcpstates_p, tcpstate, "gc stale");
            }
        }
    }
    next_gc = t + TCP_GC_TIME;
    return;
}

tcpstate_ptr tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t)
{
    tcpstate_list *tcpstates_p = NULL;
    tcpstate_ptr tcpstate = NULL;
    struct tcpstate this_tcpstate;
    static int gc_counter = 0;

    if (tcpstate_hashtbl == NULL) return (NULL);

    /* Garbage collect every (GC_COUNTER_MAX) TCP packets */
    if (gc_counter >= GC_COUNTER_MAX) {
        tcpstate_gc(t);
        gc_counter = 0;
    } else {
        gc_counter++;
    }

    this_tcpstate.saddr = from;
    this_tcpstate.daddr = to;
    this_tcpstate.sport = sport;
    this_tcpstate.dport = dport;

    tcpstates_p = hash_find (&this_tcpstate, tcpstate_hashtbl);
    if (tcpstates_p != NULL) {
        for (tcpstate = HEAD(*tcpstates_p);
             tcpstate != NULL;
             tcpstate = NEXT(tcpstate, link)) {
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
    }
    return (tcpstate);
}

tcpstate_ptr _curr_tcpstate = 0;

tcpstate_ptr tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport)
{
    tcpstate_list *tcpstates_p = NULL;
    struct tcpstate tmp_tcpstate;

    tmp_tcpstate.saddr = from;
    tmp_tcpstate.daddr = to;
    tmp_tcpstate.sport = sport;
    tmp_tcpstate.dport = dport;

    tcpstates_p = hash_find (&tmp_tcpstate, tcpstate_hashtbl);
    if (tcpstates_p == NULL) {
        tcpstates_p = calloc (1, sizeof (*tcpstates_p));
        assert (tcpstates_p);
        INIT_LIST (*tcpstates_p);
        hash_add (&tmp_tcpstate, tcpstates_p, tcpstate_hashtbl);
    }

    tcpstate_ptr tcpstate = calloc(1, sizeof *tcpstate);
    if (tcpstate == NULL) {
        /* Out of memory; recycle the least recently used */
        logerr("warning: out of memory, "
               "discarding some TCP state early");
        tcpstate = TAIL(*tcpstates_p);
        assert(tcpstate != NULL);
        UNLINK(*tcpstates_p, tcpstate, link);
        if (tcpstate->reasm) {
            tcpreasm_free(tcpstate->reasm);
        }
        if (_curr_tcpstate == tcpstate) {
            _curr_tcpstate = 0;
        }
        memset(tcpstate, 0, sizeof(*tcpstate));
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

tcpstate_ptr tcpstate_getcurr(void)
{
    return _curr_tcpstate;
}

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

/* Discard this packet.  If it's part of TCP stream, all subsequent pkts on
 * the same tcp stream will also be discarded. */
void tcpstate_discard(tcpstate_ptr tcpstate, const char* msg)
{
    tcpstate_list *tcpstates_p;
    if (dumptrace >= 3 && msg)
        fprintf(stderr, "discarding packet: %s\n", msg);
    if (tcpstate) {
        tcpstates_p = hash_find (tcpstate, tcpstate_hashtbl);
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
