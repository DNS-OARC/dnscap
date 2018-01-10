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

#include "dnscap_common.h"

#ifndef __dnscap_dump_cbor_h
#define __dnscap_dump_cbor_h

#define DUMP_CBOR_OK 0
#define DUMP_CBOR_EINVAL 1
#define DUMP_CBOR_ENOMEM 2
#define DUMP_CBOR_ECBOR 3
#define DUMP_CBOR_ELDNS 4
#define DUMP_CBOR_EWRITE 5
#define DUMP_CBOR_FLUSH 6
#define DUMP_CBOR_ENOSUP 7

/*
typedef struct cbor_stringref cbor_stringref_t;
struct cbor_stringref {
    char *string;
    size_t ref;
};
*/

int cbor_set_size(size_t size);
int cbor_set_reserve(size_t reserve);
int output_cbor(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* payload, size_t payloadlen);
int dump_cbor();
int have_cbor_support();

#endif /* __dnscap_dump_cbor_h */
