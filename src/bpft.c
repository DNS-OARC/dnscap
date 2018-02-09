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

#include "config.h"

#include "bpft.h"
#include "iaddr.h"

void prepare_bpft(void)
{
    unsigned  udp10_mbs, udp10_mbc, udp11_mbs, udp11_mbc;
    text_list bpfl;
    text_ptr  text;
    size_t    len;

    /* Prepare the must-be-set and must-be-clear tests. */
    udp10_mbs = udp10_mbc = udp11_mbs = udp11_mbc = 0U;
    if ((dir_wanted & DIR_INITIATE) != 0) {
        if ((dir_wanted & DIR_RESPONSE) == 0)
            udp10_mbc |= UDP10_QR_MASK;
    } else if ((dir_wanted & DIR_RESPONSE) != 0) {
        udp10_mbs |= UDP10_QR_MASK;
    }
    if ((msg_wanted & MSG_UPDATE) != 0) {
        if ((msg_wanted & (MSG_QUERY | MSG_NOTIFY)) == 0)
            udp10_mbs |= (ns_o_update << UDP10_OP_SHIFT);
    } else if ((msg_wanted & MSG_NOTIFY) != 0) {
        if ((msg_wanted & (MSG_QUERY | MSG_UPDATE)) == 0)
            udp10_mbs |= (ns_o_notify << UDP10_OP_SHIFT);
    } else if ((msg_wanted & MSG_QUERY) != 0) {
        udp10_mbc |= UDP10_OP_MASK;
    }
    if (err_wanted == ERR_NO) {
        udp10_mbc |= UDP10_TC_MASK;
        udp11_mbc |= UDP11_RC_MASK;
    }

    /*
 * Model
 * (vlan) and (transport)
 * (vlan) and ((icmp) or (frags) or (dns))
 * (vlan) and ((icmp) or (frags) or ((ports) and (hosts)))
 * (vlan) and ((icmp) or (frags) or (((tcp) or (udp)) and (hosts)))
 * [(vlan) and] ( [(icmp) or] [(frags) or] ( ( [(tcp) or] (udp) ) [and (hosts)] ) )
 */

    /* Make a BPF program to do early course kernel-level filtering. */
    INIT_LIST(bpfl);
    len = 0;
    if (!EMPTY(vlans_excl))
        len += text_add(&bpfl, "vlan and ("); /* vlan and ( transports ...  */
    else
        len += text_add(&bpfl, "("); /* ( transports ...  */
    if (wanticmp) {
        len += text_add(&bpfl, " ( ip proto 1 or ip proto 58 ) or");
    }
    if (wantfrags) {
        len += text_add(&bpfl, " ( ip[6:2] & 0x1fff != 0 or ip6[6] = 44 ) or");
    }
    len += text_add(&bpfl, " ("); /* ( dns ...  */
    len += text_add(&bpfl, " ("); /* ( ports ...  */
    if (wanttcp) {
        len += text_add(&bpfl, " ( tcp port %d ) or", dns_port);
        /* tcp packets can be filtered by initiators/responders, but
         * not mbs/mbc. */
    }
    len += text_add(&bpfl, " ( udp port %d", dns_port);
    if (!v6bug) {
        if (udp10_mbc != 0)
            len += text_add(&bpfl, " and udp[10] & 0x%x = 0",
                udp10_mbc);
        if (udp10_mbs != 0)
            len += text_add(&bpfl, " and udp[10] & 0x%x = 0x%x",
                udp10_mbs, udp10_mbs);
        if (udp11_mbc != 0)
            len += text_add(&bpfl, " and udp[11] & 0x%x = 0",
                udp11_mbc);
        /* Dead code, udp11_mbs never set
        if (udp11_mbs != 0)
            len += text_add(&bpfl, " and udp[11] & 0x%x = 0x%x",
                    udp11_mbs, udp11_mbs);
*/

        if (err_wanted != ERR_NO) {
            len += text_add(&bpfl, " and (");
            if ((err_wanted & ERR_TRUNC) != 0) {
                len += text_add(&bpfl, " udp[10] & 0x%x = 0x%x or", UDP10_TC_MASK, UDP10_TC_MASK);
            }
            len += text_add(&bpfl, " 0x%x << (udp[11] & 0xf) & 0x%x != 0 )", ERR_RCODE_BASE, err_wanted);
        }
    }
    len += text_add(&bpfl, " )"); /*  ... udp 53 ) */
    len += text_add(&bpfl, " )"); /*  ... ports ) */
    if (options.bpf_hosts_apply_all) {
        len += text_add(&bpfl, " )"); /*  ... dns ) */
        len += text_add(&bpfl, " )"); /* ... transport ) */
    }
    if (!EMPTY(initiators) || !EMPTY(responders)) {
        const char* or = "or", *lp = "(", *sep;
        endpoint_ptr ep;

        len += text_add(&bpfl, " and host");
        sep = lp;
        for (ep = HEAD(initiators);
             ep != NULL;
             ep = NEXT(ep, link)) {
            len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
            sep = or ;
        }
        for (ep = HEAD(responders);
             ep != NULL;
             ep = NEXT(ep, link)) {
            len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
            sep = or ;
        }
        len += text_add(&bpfl, " )");
    }
    if (!EMPTY(not_initiators) || !EMPTY(not_responders)) {
        const char* or = "or", *lp = "(", *sep;
        endpoint_ptr ep;

        len += text_add(&bpfl, " and not host");
        sep = lp;
        for (ep = HEAD(not_initiators);
             ep != NULL;
             ep = NEXT(ep, link)) {
            len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
            sep = or ;
        }
        for (ep = HEAD(not_responders);
             ep != NULL;
             ep = NEXT(ep, link)) {
            len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
            sep = or ;
        }
        len += text_add(&bpfl, " )");
    }
    if (!options.bpf_hosts_apply_all) {
        len += text_add(&bpfl, " )"); /*  ... dns ) */
        len += text_add(&bpfl, " )"); /* ... transport ) */
    }
    if (extra_bpf)
        len += text_add(&bpfl, " and ( %s )", extra_bpf);

    bpft = calloc(len + 1, sizeof(char));
    assert(bpft != NULL);
    for (text = HEAD(bpfl);
         text != NULL;
         text = NEXT(text, link))
        strcat(bpft, text->text);
    text_free(&bpfl);
    if (!EMPTY(vlans_incl)) {
        static char* bpft_vlan;
        len       = (2 * strlen(bpft)) + 64; /* add enough for the extra in snprintf() below */
        bpft_vlan = calloc(len, sizeof(char));
        assert(bpft_vlan != NULL);
        snprintf(bpft_vlan, len, "( %s ) or ( vlan and ( %s ) )", bpft, bpft);
        bpft = realloc(bpft, len);
        assert(bpft != NULL);
        strcpy(bpft, bpft_vlan);
        free(bpft_vlan);
    }
    if (dumptrace >= 1)
        fprintf(stderr, "%s: \"%s\"\n", ProgramName, bpft);
}

size_t text_add(text_list* list, const char* fmt, ...)
{
    text_ptr text;
    va_list  ap;
    int      len;

    text = calloc(1, sizeof *text);
    assert(text != NULL);
    INIT_LINK(text, link);
    va_start(ap, fmt);
    len = vasprintf(&text->text, fmt, ap);
    assert(len >= 0);
    va_end(ap);
    APPEND(*list, text, link);
    return (len);
}

void text_free(text_list* list)
{
    text_ptr text;

    while ((text = HEAD(*list)) != NULL) {
        UNLINK(*list, text, link);
        free(text);
    }
}
