/*
 * Copyright (c) 2016-2024 OARC, Inc.
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

#ifndef __dnscap_hashtbl_h
#define __dnscap_hashtbl_h

#define HASHTBL_EARGS -1
#define HASHTBL_ENOMEM -2

typedef struct hashitem hashitem;

struct hashitem {
    const void* key;
    void*       data;
    hashitem*   next;
};

typedef unsigned int (*hashkey_func)(const void* key);
typedef int (*hashkeycmp_func)(const void* a, const void* b);
typedef void (*hashfree_func)(void* data);

typedef struct hashtbl hashtbl;
struct hashtbl {
    unsigned int modulus;
    hashitem**   items;

    hashkey_func    hasher;
    hashkeycmp_func keycmp;
    hashfree_func   datafree;
};

hashtbl* hash_create(unsigned int N, hashkey_func hasher, hashkeycmp_func cmp, hashfree_func datafree);
int      hash_add(const void* key, void* data, hashtbl* tbl);
void*    hash_find(const void* key, hashtbl* tbl);
void     hash_remove(const void* key, hashtbl* tbl);
void     hash_free(hashtbl* tbl);
void     hash_destroy(hashtbl* tbl);

/*
 * found in lookup3.c
 */
#include <stddef.h>
#include <stdint.h>
extern uint32_t hashlittle(const void* key, size_t length, uint32_t initval);
extern uint32_t hashbig(const void* key, size_t length, uint32_t initval);
extern uint32_t hashword(const uint32_t* k, size_t length, uint32_t initval);

#endif // __dnscap_hashtbl_h
