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

#include "hashtbl.h"

#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

hashtbl* hash_create(unsigned int N, hashkey_func hasher, hashkeycmp_func cmp, hashfree_func datafree)
{
    hashtbl* new;

    assert(N);
    assert(hasher);
    assert(cmp);

    if ((new = calloc(1, sizeof(hashtbl)))) {
        new->modulus  = N;
        new->hasher   = hasher;
        new->keycmp   = cmp;
        new->datafree = datafree;

        if (!(new->items = calloc(N, sizeof(hashitem*)))) {
            free(new);
            return 0;
        }
    }

    return new;
}

int hash_add(const void* key, void* data, hashtbl* tbl)
{
    hashitem* new, **I;
    unsigned int slot;

    if (!key || !tbl) {
        return HASHTBL_EARGS;
    }

    new = calloc(1, sizeof(hashitem));
    if (!new) {
        return HASHTBL_ENOMEM;
    }

    new->key  = key;
    new->data = data;
    slot      = tbl->hasher(key) % tbl->modulus;

    for (I = &tbl->items[slot]; *I; I = &(*I)->next)
        ;
    *I = new;

    return 0;
}

void* hash_find(const void* key, hashtbl* tbl)
{
    unsigned int slot;
    hashitem*    i;

    if (!key || !tbl) {
        return NULL;
    }

    slot = tbl->hasher(key) % tbl->modulus;

    for (i = tbl->items[slot]; i; i = i->next) {
        if (!tbl->keycmp(key, i->key))
            return i->data;
    }

    return NULL;
}

void hash_remove(const void* key, hashtbl* tbl)
{
    hashitem **I, *i;
    int        slot;

    if (!key || !tbl) {
        return;
    }

    slot = tbl->hasher(key) % tbl->modulus;

    for (I = &tbl->items[slot]; *I; I = &(*I)->next) {
        if (!tbl->keycmp(key, (*I)->key)) {
            i  = *I;
            *I = (*I)->next;
            if (tbl->datafree)
                tbl->datafree(i->data);
            free(i);
            break;
        }
    }
}

void hash_free(hashtbl* tbl)
{
    hashitem *i, *next;
    int       slot;

    if (!tbl) {
        return;
    }

    for (slot = 0; slot < tbl->modulus; slot++) {
        for (i = tbl->items[slot]; i; i = next) {
            next = i->next;
            if (tbl->datafree)
                tbl->datafree(i->data);
            free(i);
        }
        tbl->items[slot] = 0;
    }
}

void hash_destroy(hashtbl* tbl)
{
    if (!tbl) {
        return;
    }

    hash_free(tbl);
    free(tbl->items);
    free(tbl);
}
