/*
 * Copyright (c) 2018-2025 OARC, Inc.
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

#define DNS_MSG_HDR_SZ 12
#define RFC1035_MAXLABELSZ 63
#define nptohs(p) ((((uint8_t*)(p))[0] << 8) | ((uint8_t*)(p))[1])

static int rfc1035NameSkip(const u_char* buf, size_t sz, off_t* off)
{
    unsigned char c;
    size_t        len;
    /*
     * loop_detect[] tracks which position in the DNS message it has
     * jumped to so it can't jump to the same twice, aka loop
     */
    static unsigned char loop_detect[0x3FFF] = { 0 };
    do {
        if ((*off) >= sz)
            break;
        c = *(buf + (*off));
        if (c > 191) {
            /* blasted compression */
            int            rc;
            unsigned short s;
            off_t          ptr, loop_ptr;
            s = nptohs(buf + (*off));
            (*off) += sizeof(s);
            /* Sanity check */
            if ((*off) >= sz)
                return 1; /* message too short */
            ptr = s & 0x3FFF;
            /* Make sure the pointer is inside this message */
            if (ptr >= sz)
                return 2; /* bad compression ptr */
            if (ptr < DNS_MSG_HDR_SZ)
                return 2; /* bad compression ptr */
            if (loop_detect[ptr])
                return 4; /* compression loop */
            loop_detect[(loop_ptr = ptr)] = 1;

            rc = rfc1035NameSkip(buf, sz, &ptr);

            loop_detect[loop_ptr] = 0;
            return rc;
        } else if (c > RFC1035_MAXLABELSZ) {
            /*
             * "(The 10 and 01 combinations are reserved for future use.)"
             */
            return 3; /* reserved label/compression flags */
        } else {
            (*off)++;
            len = (size_t)c;
            if (len == 0)
                break;
            if ((*off) + len > sz)
                return 4; /* message is too short */
            (*off) += len;
        }
    } while (c > 0);
    return 0;
}

static off_t skip_question(const u_char* buf, int len, off_t offset)
{
    if (rfc1035NameSkip(buf, len, &offset))
        return 0;
    if (offset + 4 > len)
        return 0;
    offset += 4;
    return offset;
}

static off_t skip_rr(const u_char* buf, int len, off_t offset)
{
    if (rfc1035NameSkip(buf, len, &offset))
        return 0;
    if (offset + 10 > len)
        return 0;
    unsigned short us = nptohs(buf + offset + 8);
    offset += 10;
    if (offset + us > len)
        return 0;
    offset += us;
    return offset;
}

#define EDNS0_TYPE_ECS 8

typedef void (*edns0_ecs_cb)(int family, u_char* buf, size_t len);

static void process_edns0_options(u_char* buf, int len, edns0_ecs_cb cb)
{
    unsigned short edns0_type;
    unsigned short edns0_len;
    off_t          offset = 0;

    while (len >= 4) {
        edns0_type = nptohs(buf + offset);
        edns0_len  = nptohs(buf + offset + 2);
        if (len < 4 + edns0_len)
            break;
        if (edns0_type == EDNS0_TYPE_ECS) {
            if (edns0_len < 5)
                break;
            if (cb)
                cb(nptohs(buf + offset + 4), buf + offset + 8, edns0_len - 4);
        }
        offset += 4 + edns0_len;
        len -= 4 + edns0_len;
    }
}

#define T_OPT 41

static off_t grok_additional_for_opt_rr(u_char* buf, int len, off_t offset, edns0_ecs_cb cb)
{
    unsigned short us;
    /*
     * OPT RR for EDNS0 MUST be 0 (root domain), so if the first byte of
     * the name is anything it can't be a valid EDNS0 record.
     */
    if (*(buf + offset)) {
        if (rfc1035NameSkip(buf, len, &offset))
            return 0;
        if (offset + 10 > len)
            return 0;
    } else {
        offset++;
        if (offset + 10 > len)
            return 0;
        if (nptohs(buf + offset) == T_OPT) {
            u_char version = *(buf + offset + 5);
            us             = nptohs(buf + offset + 8); // rd len
            offset += 10;
            if (offset + us > len)
                return 0;
            if (!version && us > 0)
                process_edns0_options(buf + offset, us, cb);
            offset += us;
            return offset;
        }
    }
    /* get rdlength */
    us = nptohs(buf + offset + 8);
    offset += 10;
    if (offset + us > len)
        return 0;
    offset += us;
    return offset;
}

static void parse_for_edns0_ecs(u_char* payload, size_t payloadlen, edns0_ecs_cb cb)
{
    off_t offset;
    int   qdcount, ancount, nscount, arcount;

    qdcount = nptohs(payload + 4);
    ancount = nptohs(payload + 6);
    nscount = nptohs(payload + 8);
    arcount = nptohs(payload + 10);

    offset = DNS_MSG_HDR_SZ;

    while (qdcount > 0 && offset < payloadlen) {
        if (!(offset = skip_question(payload, payloadlen, offset))) {
            return;
        }
        qdcount--;
    }

    while (ancount > 0 && offset < payloadlen) {
        if (!(offset = skip_rr(payload, payloadlen, offset))) {
            return;
        }
        ancount--;
    }

    while (nscount > 0 && offset < payloadlen) {
        if (!(offset = skip_rr(payload, payloadlen, offset))) {
            return;
        }
        nscount--;
    }

    while (arcount > 0 && offset < payloadlen) {
        if (!(offset = grok_additional_for_opt_rr(payload, payloadlen, offset, cb))) {
            return;
        }
        arcount--;
    }
}