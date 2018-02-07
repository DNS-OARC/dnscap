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

#include "tcpstate.h"
#include "iaddr.h"
#include "log.h"
#include "tcpreasm.h"

#define MAX_TCP_IDLE_TIME 600
#define MAX_TCP_IDLE_COUNT 4096
#define TCP_GC_TIME 60

tcpstate_ptr tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t)
{
    static time_t next_gc = 0;
    tcpstate_ptr  tcpstate;

    for (tcpstate = HEAD(tcpstates);
         tcpstate != NULL;
         tcpstate = NEXT(tcpstate, link)) {
        if (ia_equal(tcpstate->saddr, from) && ia_equal(tcpstate->daddr, to) && tcpstate->sport == sport && tcpstate->dport == dport)
            break;
    }
    if (tcpstate != NULL) {
        tcpstate->last_use = t;
        if (tcpstate != HEAD(tcpstates)) {
            /* move to beginning of list */
            UNLINK(tcpstates, tcpstate, link);
            PREPEND(tcpstates, tcpstate, link);
        }
    }

    if (t >= next_gc || tcpstate_count > MAX_TCP_IDLE_COUNT) {
        /* garbage collect stale states */
        time_t min_last_use = t - MAX_TCP_IDLE_TIME;
        while ((tcpstate = TAIL(tcpstates)) && tcpstate->last_use < min_last_use) {
            UNLINK(tcpstates, tcpstate, link);
            tcpstate_count--;
        }
        next_gc = t + TCP_GC_TIME;
    }

    return tcpstate;
}

tcpstate_ptr tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport)
{

    tcpstate_ptr tcpstate = calloc(1, sizeof *tcpstate);
    if (tcpstate == NULL) {
        /* Out of memory; recycle the least recently used */
        logerr("warning: out of memory, "
               "discarding some TCP state early");
        tcpstate = TAIL(tcpstates);
        assert(tcpstate != NULL);
    } else {
        tcpstate_count++;
    }
    tcpstate->saddr = from;
    tcpstate->daddr = to;
    tcpstate->sport = sport;
    tcpstate->dport = dport;
    INIT_LINK(tcpstate, link);
    PREPEND(tcpstates, tcpstate, link);
    return tcpstate;
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
        free(tcpstate);
        tcpstate_count--;
        return;
    }
}

tcpstate_ptr _curr_tcpstate = 0;

tcpstate_ptr tcpstate_getcurr(void)
{
    return _curr_tcpstate;
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
