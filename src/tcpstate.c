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
#include "hashtbl.h"

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#define MAX_TCP_IDLE_TIME 600
#define MAX_TCP_IDLE_COUNT 4096
#define TCP_GC_TIME 60

static hashtbl* _hash = 0;

tcpstate_ptr tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t)
{
    static time_t next_gc = 0;
    tcpstate_ptr  tcpstate;

#ifndef __clang_analyzer__
    /* disabled during scan-build due to false-positives */
    if (t >= next_gc || tcpstate_count > MAX_TCP_IDLE_COUNT) {
        /* garbage collect stale states */
        while ((tcpstate = TAIL(tcpstates)) && tcpstate->last_use < t - MAX_TCP_IDLE_TIME) {
            tcpstate_discard(tcpstate, "gc stale");
        }
        next_gc = t + TCP_GC_TIME;
    }
#endif

    tcpstate_key key = {
        .saddr = &from,
        .daddr = &to,
        .sport = sport,
        .dport = dport
    };

    tcpstate = hash_find(&key, _hash);

    if (tcpstate != NULL) {
        tcpstate->last_use = t;
        if (tcpstate != HEAD(tcpstates)) {
            /* move to beginning of list */
            UNLINK(tcpstates, tcpstate, link);
            PREPEND(tcpstates, tcpstate, link);
        }
    }

    return tcpstate;
}

unsigned int tcpstate_hash(const tcpstate_key* key)
{
    uint32_t h = 0;

    switch (key->saddr->af) {
    case AF_INET:
        h = hashword(&key->saddr->u.a4.s_addr, 1, h);
        break;
    case AF_INET6:
        h = hashword(key->saddr->u.a6.s6_addr32, 4, h);
        break;
    }

    switch (key->daddr->af) {
    case AF_INET:
        h = hashword(&key->daddr->u.a4.s_addr, 1, h);
        break;
    case AF_INET6:
        h = hashword(key->daddr->u.a6.s6_addr32, 4, h);
        break;
    }

    uint32_t p = (key->sport << 16) | (key->dport & 0xffff);
    return hashword(&p, 1, h);
}

int tcpstate_cmp(const tcpstate_key* a, const tcpstate_key* b)
{
    if (ia_equalp(a->saddr, b->saddr) && ia_equalp(a->daddr, b->daddr) && a->sport == b->sport && a->dport == b->dport)
        return 0;
    return 1;
}

tcpstate_ptr _curr_tcpstate = 0;

tcpstate_ptr tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport)
{
    if (!_hash) {
        _hash = hash_create(65535, (hashkey_func)tcpstate_hash, (hashkeycmp_func)tcpstate_cmp, 0);
        assert(_hash);
    }
    tcpstate_ptr tcpstate = calloc(1, sizeof *tcpstate);
    if (tcpstate == NULL) {
        /* Out of memory; recycle the least recently used */
        logerr("warning: out of memory, "
               "discarding some TCP state early");
        tcpstate = TAIL(tcpstates);
        assert(tcpstate != NULL);
        UNLINK(tcpstates, tcpstate, link);
        if (tcpstate->reasm) {
            tcpreasm_free(tcpstate->reasm);
        }
        if (_curr_tcpstate == tcpstate) {
            _curr_tcpstate = 0;
        }
        hash_remove(&tcpstate->key, _hash);
        memset(tcpstate, 0, sizeof(*tcpstate));
    } else {
        tcpstate_count++;
    }
    tcpstate->saddr = from;
    tcpstate->daddr = to;
    tcpstate->sport = sport;
    tcpstate->dport = dport;
    INIT_LINK(tcpstate, link);
    PREPEND(tcpstates, tcpstate, link);

    tcpstate->key.saddr = &tcpstate->saddr;
    tcpstate->key.daddr = &tcpstate->daddr;
    tcpstate->key.sport = sport;
    tcpstate->key.dport = dport;
    hash_add(&tcpstate->key, tcpstate, _hash);

    return tcpstate;
}

tcpstate_ptr tcpstate_getcurr(void)
{
    return _curr_tcpstate;
}

/* Discard this packet.  If it's part of TCP stream, all subsequent pkts on
 * the same tcp stream will also be discarded. */
void tcpstate_discard(tcpstate_ptr tcpstate, const char* msg)
{
    if (dumptrace >= 3 && msg)
        fprintf(stderr, "discarding packet: %s\n", msg);
    if (tcpstate) {
        UNLINK(tcpstates, tcpstate, link);
        if (tcpstate->reasm) {
            tcpreasm_free(tcpstate->reasm);
        }
        hash_remove(&tcpstate->key, _hash);
        free(tcpstate);
        if (_curr_tcpstate == tcpstate) {
            _curr_tcpstate = 0;
        }
        tcpstate_count--;
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

void tcpstate_free(tcpstate_ptr tcpstate)
{
    if (tcpstate) {
        UNLINK(tcpstates, tcpstate, link);
        if (tcpstate->reasm) {
            tcpreasm_free(tcpstate->reasm);
        }
        hash_remove(&tcpstate->key, _hash);
        free(tcpstate);
        if (_curr_tcpstate == tcpstate) {
            _curr_tcpstate = 0;
        }
        tcpstate_count--;
    }
}