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

#include "dump_cds.h"
#include "dnscap.h"
#include "hashtbl.h"
#include "iaddr.h"

#if HAVE_LIBTINYCBOR

#include <stdlib.h>
#if HAVE_CBOR_CBOR_H
#include <cbor/cbor.h>
#endif
#if HAVE_CBOR_H
#include <cbor.h>
#endif
#include <assert.h>

#define need8(v, p, l, d)                                           \
    if (l < 1) {                                                    \
        if (sizeof(d) > 1)                                          \
            fprintf(stderr, "cds need 1B/8b, had %lu: %s\n", l, d); \
        return 1;                                                   \
    }                                                               \
    v = *p;                                                         \
    p += 1;                                                         \
    l -= 1

#define need16(v, p, l, d)                                           \
    if (l < 2) {                                                     \
        if (sizeof(d) > 1)                                           \
            fprintf(stderr, "cds need 2B/16b, had %lu: %s\n", l, d); \
        return 1;                                                    \
    }                                                                \
    v = (*p << 8) + *(p + 1);                                        \
    p += 2;                                                          \
    l -= 2

#define need32(v, p, l, d)                                           \
    if (l < 4) {                                                     \
        if (sizeof(d) > 1)                                           \
            fprintf(stderr, "cds need 4B/32b, had %lu: %s\n", l, d); \
        return 1;                                                    \
    }                                                                \
    v = (*p << 24) + (*(p + 1) << 16) + (*(p + 2) << 8) + *(p + 3);  \
    p += 4;                                                          \
    l -= 4

#define need64(v, p, l, d)                                                                                                                      \
    if (l < 8) {                                                                                                                                \
        if (sizeof(d) > 1)                                                                                                                      \
            fprintf(stderr, "cds need 8B/64b, had %lu: %s\n", l, d);                                                                            \
        return 1;                                                                                                                               \
    }                                                                                                                                           \
    v = (*p << 56) + (*(p + 1) << 48) + (*(p + 2) << 40) + (*(p + 3) << 32) + (*(p + 4) << 24) + (*(p + 5) << 16) + (*(p + 6) << 8) + *(p + 7); \
    p += 8;                                                                                                                                     \
    l -= 8

#define needxb(b, x, p, l, d)                                             \
    if (l < x) {                                                          \
        if (sizeof(d) > 1)                                                \
            fprintf(stderr, "cds need %d bytes, had %lu: %s\n", x, l, d); \
        return 1;                                                         \
    }                                                                     \
    memcpy(b, p, x);                                                      \
    p += x;                                                               \
    l -= x

#define advancexb(x, p, l, d)                                                          \
    if (l < x) {                                                                       \
        if (sizeof(d) > 1)                                                             \
            fprintf(stderr, "cds needed to advance %d bytes, had %lu: %s\n", x, l, d); \
        return 1;                                                                      \
    }                                                                                  \
    p += x;                                                                            \
    l -= x

static uint8_t* cbor_buf              = 0;
static uint8_t* cbor_buf_p            = 0;
static size_t   cbor_size             = 1024 * 1024;
static uint8_t* message_buf           = 0;
static size_t   message_size          = 64 * 1024;
static int      cbor_flushed          = 1;
static hashtbl* rdata_tbl             = 0;
static size_t   MAX_RLABELS           = CDS_DEFAULT_MAX_RLABELS;
static size_t   MIN_RLABEL_SIZE       = CDS_DEFAULT_MIN_RLABEL_SIZE;
static int      use_rdata_index       = 0;
static int      use_rdata_rindex      = 0;
static size_t   RDATA_RINDEX_SIZE     = CDS_DEFAULT_RDATA_RINDEX_SIZE;
static size_t   RDATA_RINDEX_MIN_SIZE = CDS_DEFAULT_RDATA_RINDEX_MIN_SIZE;
static size_t   RDATA_INDEX_MIN_SIZE  = CDS_DEFAULT_RDATA_INDEX_MIN_SIZE;

struct rdata;
struct rdata {
    struct rdata* prev;
    struct rdata* next;
    uint8_t*      data;
    size_t        len;
    size_t        idx;
};

struct last {
    my_bpftimeval ts;
    ip_header_t   ip;

    uint16_t dns_type;
    uint16_t dns_class;
    uint32_t dns_ttl;

    dns_rlabel_t* dns_rlabel;
    dns_rlabel_t* dns_rlabel_last;
    size_t        dns_rlabels;

    size_t        rdata_index;
    size_t        rdata_num;
    struct rdata* rdata;
    struct rdata* rdata_last;
};
static struct last last;

/*
 * Set/Get
 */

int cds_set_cbor_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    cbor_size = size;
    if (message_size > cbor_size) {
        message_size = cbor_size;
    }

    return DUMP_CDS_OK;
}

int cds_set_message_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    message_size = size;
    if (message_size > cbor_size) {
        message_size = cbor_size;
    }

    return DUMP_CDS_OK;
}

int cds_set_max_rlabels(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    MAX_RLABELS = size;

    return DUMP_CDS_OK;
}

int cds_set_min_rlabel_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    MIN_RLABEL_SIZE = size;

    return DUMP_CDS_OK;
}

int cds_set_use_rdata_index(int use)
{
    use_rdata_index = use ? 1 : 0;

    return DUMP_CDS_OK;
}

int cds_set_use_rdata_rindex(int use)
{
    use_rdata_rindex = use ? 1 : 0;

    return DUMP_CDS_OK;
}

int cds_set_rdata_index_min_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    RDATA_INDEX_MIN_SIZE = size;

    return DUMP_CDS_OK;
}

int cds_set_rdata_rindex_min_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    RDATA_RINDEX_MIN_SIZE = size;

    return DUMP_CDS_OK;
}

int cds_set_rdata_rindex_size(size_t size)
{
    if (!size) {
        return DUMP_CDS_EINVAL;
    }

    RDATA_RINDEX_SIZE = size;

    return DUMP_CDS_OK;
}

/*
 * DNS
 */

static int check_dns_label(size_t* labels, uint8_t** p, size_t* l)
{
    uint8_t len;

    while (1) {
        need8(len, *p, *l, "");
        *labels += 1;

        if ((len & 0xc0) == 0xc0) {
            advancexb(1, *p, *l, "");
            break;
        } else if (len & 0xc0) {
            break;
        } else if (len) {
            advancexb(len, *p, *l, "");
        } else {
            break;
        }
    }

    return 0;
}

static unsigned int rdata_hash(const void* _item)
{
    const struct rdata* item = (const struct rdata*)_item;
    size_t              n, o, p;
    unsigned int        key = 0;

    for (n = 0, o = 0, p = 0; n < item->len; n++) {
        p |= item->data[n] << (o * 8);
        o++;
        if (o > 3) {
            key ^= p;
            p = 0;
            o = 0;
        }
    }
    if (o) {
        key ^= p;
    }

    return key;
}

static int rdata_cmp(const void* _a, const void* _b)
{
    const struct rdata *a = (const struct rdata*)_a, *b = (const struct rdata*)_b;

    if (a->len == b->len) {
        return memcmp(a->data, b->data, a->len);
    } else if (a->len < b->len)
        return -1;
    return 1;
}

static void rdata_free(void* d)
{
    struct rdata* item = (struct rdata*)d;

    if (item) {
        if (item->data) {
            free(item->data);
        }
        free(item);
    }
}

static int rdata_add(uint8_t* p, size_t len)
{
    struct rdata* key;

    if (len < RDATA_INDEX_MIN_SIZE)
        return 1;

    if (!(key = calloc(1, sizeof(struct rdata)))) {
        return 0;
    }
    if (!(key->data = calloc(1, len))) {
        free(key);
        return 0;
    }

    key->len = len;
    memcpy(key->data, p, len);
    key->idx = last.rdata_index++;

    /*    printf("rdata_add  %u: ", rdata_hash(key));*/
    /*    {*/
    /*        size_t n = len;*/
    /*        uint8_t* x = p;*/
    /*        while (n--) {*/
    /*            printf("%02x", *x);*/
    /*            x++;*/
    /*        }*/
    /*    }*/
    /*    printf("\n");*/
    hash_add(key, key, rdata_tbl);

    return 0;
}

static size_t rdata_find(uint8_t* p, size_t len, size_t* found)
{
    struct rdata  key;
    struct rdata* r;

    if (len < RDATA_INDEX_MIN_SIZE)
        return 1;

    key.data = p;
    key.len  = len;

    /*    printf("rdata_find %u: ", rdata_hash(&key));*/
    /*    {*/
    /*        size_t n = len;*/
    /*        uint8_t* x = p;*/
    /*        while (n--) {*/
    /*            printf("%02x", *x);*/
    /*            x++;*/
    /*        }*/
    /*    }*/
    /*    printf("\n");*/

    if ((r = hash_find(&key, rdata_tbl))) {
        /*        printf("rdata found %lu at %lu\n", len, found->idx);*/
        *found = r->idx;
        return 0;
    }

    return 1;
}

int rdata_find2(uint8_t* p, size_t len, size_t* found)
{
    struct rdata* r = last.rdata;
    size_t        n = 0;

    if (len < RDATA_RINDEX_MIN_SIZE)
        return 1;

    while (r) {
        if (r->len == len && !memcmp(p, r->data, len)) {
            break;
        }
        r = r->next;
        n++;
    }
    if (r) {
        /*        printf("rdata found at %lu: ", n);*/
        /*        {*/
        /*            size_t n = len;*/
        /*            uint8_t* x = p;*/
        /*            while (n--) {*/
        /*                printf("%02x", *x);*/
        /*                x++;*/
        /*            }*/
        /*        }*/
        /*        printf("\n");*/

        if (last.rdata != r) {
            struct rdata *prev = r->prev, *next = r->next;

            if (prev) {
                prev->next = next;
            }
            if (next) {
                next->prev = prev;
            }

            r->prev          = 0;
            r->next          = last.rdata;
            last.rdata->prev = r;
            last.rdata       = r;
        }

        *found = n;
        return 0;
    }

    return 1;
}

int rdata_add2(uint8_t* p, size_t len)
{
    struct rdata* r;

    if (len < RDATA_RINDEX_MIN_SIZE)
        return 1;

    if (!(r = calloc(1, sizeof(struct rdata)))) {
        return -1;
    }
    if (!(r->data = calloc(1, len))) {
        free(r);
        return -1;
    }

    r->len = len;
    memcpy(r->data, p, len);

    /*    printf("rdata_add: ");*/
    /*    {*/
    /*        size_t n = len;*/
    /*        uint8_t* x = p;*/
    /*        while (n--) {*/
    /*            printf("%02x", *x);*/
    /*            x++;*/
    /*        }*/
    /*    }*/
    /*    printf("\n");*/

    if (last.rdata) {
        last.rdata->prev = r;
    }
    r->next    = last.rdata;
    last.rdata = r;
    last.rdata_num++;

    if (last.rdata_last) {
        if (last.rdata_num >= RDATA_RINDEX_SIZE) {
            r = last.rdata_last;

            last.rdata_last       = r->prev;
            last.rdata_last->next = 0;
            last.rdata_num--;
            free(r->data);
            free(r);
        }
    } else {
        last.rdata_last = r;
    }

    return 0;
}

static int parse_dns_rr(char is_q, dns_rr_t* rr, size_t expected_rrs, size_t* actual_rrs, uint8_t** p, size_t* l)
{
    uint8_t      len;
    uint8_t*     p2;
    size_t       l2, idx;
    dns_label_t* label;
    size_t       num_labels, offset;

    while (expected_rrs--) {
        /* first pass check number of labels */
        p2 = *p;
        l2 = *l;

        if (check_dns_label(&(rr->labels), &p2, &l2)) {
            if (!rr->labels) {
                fprintf(stderr, "cds no labels\n");
                return 1;
            }
        }

        /* second pass, allocate labels and fill */
        if (!(rr->label = calloc(rr->labels, sizeof(dns_label_t)))) {
            fprintf(stderr, "cds out of memory\n");
            return -1;
        }

        *actual_rrs += 1;

        label           = rr->label;
        rr->have_labels = 1;

        while (1) {
            need8(len, *p, *l, "name length");

            if ((len & 0xc0) == 0xc0) {
                label->offset_p = *p;
                need8(label->offset, *p, *l, "name offset");
                label->offset |= (len & 0x3f) << 8;
                label->have_offset = 1;
                label->is_complete = 1;
                break;
            } else if (len & 0xc0) {
                label->extension_bits      = len;
                label->have_extension_bits = 1;
                label->is_complete         = 1;
                break;
            } else if (len) {
                label->size      = len;
                label->have_size = 1;
                label->label     = *p;
                advancexb(len, *p, *l, "name label");
                label->have_label = 1;
            } else {
                label->have_size   = 1;
                label->is_complete = 1;
                break;
            }

            label->is_complete = 1;
            label++;
        }

        need16(rr->type, *p, *l, "type");
        rr->have_type = 1;
        need16(rr->class, *p, *l, "class");
        rr->have_class = 1;

        if (!is_q) {
            need32(rr->ttl, *p, *l, "ttl");
            rr->have_ttl = 1;
            need16(rr->rdlength, *p, *l, "rdlength");
            rr->have_rdlength = 1;
            rr->rdata         = *p;
            advancexb(rr->rdlength, *p, *l, "rdata");

            if (use_rdata_index) {
                if (!rdata_find(rr->rdata, rr->rdlength, &(rr->rdata_index))) {
                    rr->have_rdata_index = 1;
                } else {
                    rdata_add(rr->rdata, rr->rdlength);
                }
            } else if (use_rdata_rindex) {
                if (!rdata_find2(rr->rdata, rr->rdlength, &(rr->rdata_rindex))) {
                    rr->have_rdata_rindex = 1;
                } else {
                    rdata_add2(rr->rdata, rr->rdlength);
                }
            }

            num_labels = offset = 0;
            switch (rr->type) {
            case 2: /* NS */
            case 3: /* MD */
            case 4: /* MF */
            case 5: /* CNAME */
            case 7: /* MB */
            case 8: /* MG */
            case 9: /* MR */
            case 12: /* PTR */
            case 30: /* NXT */
            case 39: /* DNAME */
            case 47: /* NSEC */
            case 249: /* TKEY */
            case 250: /* TSIG */
                num_labels = 1;
                break;

            case 6: /* SOA */
            case 14: /* MINFO */
            case 17: /* RP */
            case 58: /* TALINK */
                num_labels = 2;
                break;

            case 15: /* MX */
            case 18: /* AFSDB */
            case 21: /* RT */
            case 36: /* KX */
            case 107: /* LP */
                num_labels = 1;
                offset     = 2;
                break;

            case 26: /* PX */
                num_labels = 2;
                offset     = 2;
                break;

            case 24: /* SIG */
            case 46: /* RRSIG */
                num_labels = 1;
                offset     = 18;
                break;

            case 33: /* SRV */
                num_labels = 1;
                offset     = 6;
                break;

            case 35: /* NAPTR */
                num_labels = 1;
                p2         = *p;
                l2         = *l;
                advancexb(2, p2, l2, "naptr int16 #1");
                advancexb(2, p2, l2, "naptr int16 #2");
                need8(len, p2, l2, "naptr str len #1");
                advancexb(len, p2, l2, "naptr str #1");
                need8(len, p2, l2, "naptr str len #2");
                advancexb(len, p2, l2, "naptr str #2");
                need8(len, p2, l2, "naptr str len #3");
                advancexb(len, p2, l2, "naptr str #3");
                offset = p2 - *p;
                break;

            case 55: /* HIP TODO */
                break;
            }

            if (num_labels) {
                dns_rdata_t* rdata;

                rr->mixed_rdatas = num_labels + (offset ? 1 : 0) + 1;
                if (!(rr->mixed_rdata = calloc(rr->mixed_rdatas, sizeof(dns_rdata_t)))) {
                    fprintf(stderr, "cds out of memory\n");
                    return -1;
                }

                p2                   = rr->rdata;
                l2                   = rr->rdlength;
                rdata                = rr->mixed_rdata;
                rr->have_mixed_rdata = 1;

                if (offset) {
                    rdata->rdata_len = offset;
                    rdata->rdata     = p2;
                    advancexb((int)offset, p2, l2, "mixed rdata");
                    rdata->have_rdata  = 1;
                    rdata->is_complete = 1;
                    rdata++;
                }
                while (num_labels--) {
                    uint8_t* p3;
                    size_t   l3;

                    /* first pass check number of rdata labels */

                    p3 = p2;
                    l3 = l2;

                    if (check_dns_label(&(rdata->labels), &p3, &l3)) {
                        if (!rdata->labels) {
                            fprintf(stderr, "cds mixed rdata no labels\n");
                            return 1;
                        }
                    }

                    /* second pass, allocate mixed rdata */
                    if (!(rdata->label = calloc(rdata->labels, sizeof(dns_label_t)))) {
                        fprintf(stderr, "cds out of memory\n");
                        return -1;
                    }

                    label              = rdata->label;
                    rdata->have_labels = 1;
                    while (1) {
                        need8(len, p2, l2, "name length");

                        if ((len & 0xc0) == 0xc0) {
                            label->offset_p = p2;
                            need8(label->offset, p2, l2, "name offset");
                            label->offset |= (len & 0x3f) << 8;
                            label->have_offset = 1;
                            label->is_complete = 1;
                            break;
                        } else if (len & 0xc0) {
                            label->extension_bits      = len;
                            label->have_extension_bits = 1;
                            label->is_complete         = 1;
                            break;
                        } else if (len) {
                            label->size      = len;
                            label->have_size = 1;
                            label->label     = p2;
                            advancexb(len, p2, l2, "name label");
                            label->have_label = 1;
                        } else {
                            label->have_size   = 1;
                            label->is_complete = 1;
                            break;
                        }

                        label->is_complete = 1;
                        label++;
                    }
                    rdata->is_complete = 1;
                    rdata++;
                }
                if (l2) {
                    /*printf("last rdata %lu\n", l2);*/
                    rdata->rdata_len = l2;
                    rdata->rdata     = p2;
                    advancexb((int)l2, p2, l2, "mixed rdata");
                    rdata->have_rdata  = 1;
                    rdata->is_complete = 1;
                } else {
                    rr->mixed_rdatas--;
                }
            }
            rr->have_rdata = 1;
        }

        rr->is_complete = 1;
        rr++;
    }

    return 0;
}

int print_cbor = 0;

static int parse_dns(dns_t* dns, uint8_t** p, size_t* l)
{
    int ret;

    need16(dns->id, *p, *l, "dns id");
    dns->have_id = 1;
    need16(dns->raw, *p, *l, "raw dns bits");
    dns->have_raw = 1;
    need16(dns->qdcount, *p, *l, "qdcount");
    dns->have_qdcount = 1;
    need16(dns->ancount, *p, *l, "ancount");
    dns->have_ancount = 1;
    need16(dns->nscount, *p, *l, "nscount");
    dns->have_nscount = 1;
    need16(dns->arcount, *p, *l, "arcount");
    dns->have_arcount = 1;

    dns->header_is_complete = 1;

    if (dns->qdcount) {
        if (!(dns->question = calloc(dns->qdcount, sizeof(dns_rr_t)))) {
            fprintf(stderr, "cds out of memory\n");
            return -1;
        }
        ret = parse_dns_rr(1, dns->question, dns->qdcount, &(dns->questions), p, l);
        /*if (ret) printf("qr %d\n", ret);*/
        if (ret > -1 && dns->questions) {
            dns->have_questions = 1;
        }
        if (ret) {
            return ret;
        }
    }

    if (dns->ancount) {
        if (!(dns->answer = calloc(dns->ancount, sizeof(dns_rr_t)))) {
            fprintf(stderr, "cds out of memory\n");
            return -1;
        }
        ret = parse_dns_rr(0, dns->answer, dns->ancount, &(dns->answers), p, l);
        /*if (ret) printf("an %d\n", ret);*/
        if (ret > -1 && dns->answers) {
            dns->have_answers = 1;
        }
        if (ret) {
            return ret;
        }
    }

    if (dns->nscount) {
        if (!(dns->authority = calloc(dns->nscount, sizeof(dns_rr_t)))) {
            fprintf(stderr, "cds out of memory\n");
            return -1;
        }
        ret = parse_dns_rr(0, dns->authority, dns->nscount, &(dns->authorities), p, l);
        /*if (ret) { printf("ns %d %lu\n", ret, dns->authorities);*/
        /*{*/
        /*    size_t n;*/
        /*    for (n = 0; n < dns->authorities; n++) {*/
        /*        printf("%lu %d\n", n, dns->authority[n].is_complete);*/
        /*        if (!dns->authority[n].is_complete) print_cbor = 1;*/
        /*    }*/
        /*} }*/
        if (ret > -1 && dns->authorities) {
            dns->have_authorities = 1;
        }
        if (ret) {
            return ret;
        }
    }

    if (dns->arcount) {
        if (!(dns->additional = calloc(dns->arcount, sizeof(dns_rr_t)))) {
            fprintf(stderr, "cds out of memory\n");
            return -1;
        }
        ret = parse_dns_rr(0, dns->additional, dns->arcount, &(dns->additionals), p, l);
        /*if (ret) printf("ar %d\n", ret);*/
        if (ret > -1 && dns->additionals) {
            dns->have_additionals = 1;
        }
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static CborError encode_label(CborEncoder* encoder, dns_label_t* label, size_t labels)
{
    CborError   cbor_err = CborNoError;
    CborEncoder array;

    if (labels && label[labels - 1].have_size && !label[labels - 1].size) {
        labels--;
    }

    cbor_err = cbor_encoder_create_array(encoder, &array, labels);
    while (labels--) {
        if (label->have_offset) {
            if (label->have_n_offset) {
                if (cbor_err == CborNoError)
                    cbor_err = cbor_encode_uint(&array, label->n_offset);
            } else {
                if (cbor_err == CborNoError)
                    cbor_err = cbor_encode_negative_int(&array, label->offset);
            }
        } else if (label->have_extension_bits) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_simple_value(&array, label->extension_bits >> 6);
        } else if (label->have_label) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_text_string(&array, (const char*)label->label, label->size);
        } else {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_null(&array);
        }

        label++;
    }
    if (cbor_err == CborNoError)
        cbor_err = cbor_encoder_close_container_checked(encoder, &array);

    return cbor_err;
}

/*
 * OUTPUT
 */

int print_label(dns_label_t* label, size_t labels)
{
    size_t n;

    for (n = 0; n < labels; n++) {
        if (label[n].have_offset) {
            if (label[n].have_n_offset) {
                printf(" %lu", label[n].n_offset);
            } else {
                printf(" %d", -label[n].offset);
            }
        } else if (label[n].have_extension_bits) {
            printf(" %x", label[n].extension_bits);
        } else if (label[n].have_label) {
            printf(" %.*s", label[n].size, label[n].label);
        } else {
            printf(" $");
        }
    }
    return 0;
}

int print_rlabel(dns_rlabel_t* label)
{
    size_t n;

    for (n = 0; n < label->labels; n++) {
        if (label->label[n].size) {
            printf(" %.*s", label->label[n].size, label->label[n].label);
        } else if (label->label[n].have_n_offset) {
            printf(" %lu", label->label[n].n_offset);
        } else {
            printf(" $");
        }
    }
    return 0;
}

int dns_rlabel_add(dns_label_t* label, size_t labels)
{
    dns_rlabel_t* copy;
    size_t        n, size = 0;

    for (n = 0; n < labels; n++) {
        if ((label[n].have_offset && !label[n].have_n_offset)
            || label[n].have_extension_bits) {
            return 1;
        }
        if (label[n].have_size) {
            size += label[n].size;
        }
    }
    /*printf("label size: %lu\n", size);*/
    if (size < MIN_RLABEL_SIZE) {
        return 1;
    }

    if (!(copy = calloc(1, sizeof(dns_rlabel_t)))) {
        return -1;
    }

    assert(labels <= CDS_RLABEL_T_LABELS);
    copy->labels = labels;

    for (n = 0; n < labels; n++) {
        if (label[n].have_n_offset) {
            copy->label[n].have_n_offset = 1;
            copy->label[n].n_offset      = label[n].n_offset;
            continue;
        }
        if (label[n].size) {
            assert(label[n].size <= CDS_RLABEL_LABEL_T_LABEL);

            copy->label[n].size = label[n].size;
            memcpy(&(copy->label[n].label), label[n].label, label[n].size);
        }
    }

    /*printf("add"); print_label(label, labels); printf("\n");*/

    if (last.dns_rlabel) {
        last.dns_rlabel->prev = copy;
    }
    copy->next      = last.dns_rlabel;
    last.dns_rlabel = copy;
    last.dns_rlabels++;
    if (last.dns_rlabel_last) {
        if (last.dns_rlabels >= MAX_RLABELS) {
            dns_rlabel_t* remove = last.dns_rlabel_last;

            /*printf("remove %p %p\n", remove, remove->prev);*/

            last.dns_rlabel_last       = remove->prev;
            last.dns_rlabel_last->next = 0;
            free(remove);
            last.dns_rlabels--;
        }
    } else {
        last.dns_rlabel_last = copy;
    }

    return 0;
}

static size_t dns_rlabel_find(dns_label_t* label, size_t labels, size_t* rlabel_idx)
{
    size_t        n, n2, size = 0;
    dns_rlabel_t* rlabel;

    for (n = 0; n < labels; n++) {
        if ((label[n].have_offset && !label[n].have_n_offset)
            || label[n].have_extension_bits) {
            return 1;
        }
        if (label[n].have_size) {
            size += label[n].size;
        }
    }
    /*printf("label size: %lu\n", size);*/
    if (size < MIN_RLABEL_SIZE) {
        return 1;
    }

    /*printf("find"); print_label(label, labels); printf("\n");*/

    n      = 0;
    rlabel = last.dns_rlabel;
    while (rlabel) {
        if (rlabel->labels == labels) {
            /*printf("check"); print_rlabel(rlabel); printf("\n");*/

            for (n2 = 0; n2 < labels; n2++) {
                /*printf("%d %lu <> %d %lu\n", label[n2].have_n_offset, label[n2].n_offset, rlabel->label[n2].have_n_offset, rlabel->label[n2].n_offset);*/
                if (label[n2].have_n_offset
                    || rlabel->label[n2].have_n_offset) {
                    if (label[n2].n_offset == rlabel->label[n2].n_offset)
                        continue;
                } else if (label[n2].size == rlabel->label[n2].size
                           && !memcmp(label[n2].label, rlabel->label[n2].label, label[n2].size)) {
                    continue;
                }
                break;
            }

            if (n2 == labels) {
                /*printf("found at %lu: ", n); print_rlabel(rlabel); printf("\n");*/
                break;
            }
        }
        rlabel = rlabel->next;
        n++;
    }
    if (rlabel) {
        if (last.dns_rlabel != rlabel) {
            dns_rlabel_t *prev = rlabel->prev, *next = rlabel->next;

            if (prev) {
                prev->next = next;
            }
            if (next) {
                next->prev = prev;
            }

            rlabel->prev          = 0;
            rlabel->next          = last.dns_rlabel;
            last.dns_rlabel->prev = rlabel;
            last.dns_rlabel       = rlabel;
        }

        *rlabel_idx = n;
        return 0;
    }

    return 1;
}

static void free_rdata(dns_rdata_t* rdata)
{
    if (rdata->label) {
        free(rdata->label);
    }
}

static void free_rr(dns_rr_t* rr)
{
    size_t n;

    if (rr->label) {
        free(rr->label);
    }
    for (n = 0; n < rr->mixed_rdatas; n++) {
        free_rdata(&(rr->mixed_rdata[n]));
    }
    if (rr->mixed_rdata) {
        free(rr->mixed_rdata);
    }
}

static void free_dns(dns_t* dns)
{
    size_t n;

    for (n = 0; n < dns->questions; n++) {
        free_rr(&(dns->question[n]));
    }
    for (n = 0; n < dns->answers; n++) {
        free_rr(&(dns->answer[n]));
    }
    for (n = 0; n < dns->authorities; n++) {
        free_rr(&(dns->authority[n]));
    }
    for (n = 0; n < dns->additionals; n++) {
        free_rr(&(dns->additional[n]));
    }
}

void dns_rr_build_offset(dns_rr_t* rr_list, size_t count, uint16_t* offset, size_t offsets, size_t* n_offset, const u_char* payload)
{
    dns_rr_t* rrp;
    size_t    rr, n, n2;

    for (rr = 0; rr < count && *n_offset < offsets; rr++) {
        rrp = &(rr_list[rr]);

        for (n = 0; n < rrp->labels && *n_offset < offsets; n++) {
            if (rrp->label[n].size) {
                rrp->label[n].offset = rrp->label[n].label - payload - 1;
                offset[*n_offset]    = rrp->label[n].offset;
                *n_offset += 1;
            } else if (rrp->label[n].have_offset) {
                offset[*n_offset] = rrp->label[n].offset_p - payload - 1;
                *n_offset += 1;
            }

            /*                printf("%u %u %u %.*s\n",*/
            /*                    rrp->label[n].size,*/
            /*                    rrp->label[n].extension_bits,*/
            /*                    rrp->label[n].offset,*/
            /*                    rrp->label[n].size ? rrp->label[n].size : 0,*/
            /*                    rrp->label[n].size ? (char*)rrp->label[n].label : ""*/
            /*                );*/
        }
        for (n = 0; n < rrp->mixed_rdatas && *n_offset < offsets; n++) {
            for (n2 = 0; n2 < rrp->mixed_rdata[n].labels; n2++) {
                if (rrp->mixed_rdata[n].label[n2].size) {
                    rrp->mixed_rdata[n].label[n2].offset = rrp->mixed_rdata[n].label[n2].label - payload - 1;
                    offset[*n_offset]                    = rrp->mixed_rdata[n].label[n2].offset;
                    *n_offset += 1;
                } else if (rrp->mixed_rdata[n].label[n2].have_offset) {
                    offset[*n_offset] = rrp->mixed_rdata[n].label[n2].offset_p - payload - 1;
                    *n_offset += 1;
                }

                /*                    printf(" %u %u %u %.*s\n",*/
                /*                        rrp->mixed_rdata[n].label[n2].size,*/
                /*                        rrp->mixed_rdata[n].label[n2].extension_bits,*/
                /*                        rrp->mixed_rdata[n].label[n2].offset,*/
                /*                        rrp->mixed_rdata[n].label[n2].size ? rrp->mixed_rdata[n].label[n2].size : 0,*/
                /*                        rrp->mixed_rdata[n].label[n2].size ? (char*)rrp->mixed_rdata[n].label[n2].label : ""*/
                /*                    );*/
            }
        }
    }
}

void dns_rr_set_offset(dns_rr_t* rr_list, size_t count, uint16_t* offset, size_t n_offset)
{
    dns_rr_t* rrp;
    size_t    rr, n, n2, n3;

    for (rr = 0; rr < count; rr++) {
        rrp = &(rr_list[rr]);

        for (n = 0; n < rrp->labels; n++) {
            if (!rrp->label[n].size && rrp->label[n].offset) {
                for (n3 = 0; n3 < n_offset; n3++) {
                    if (rrp->label[n].offset == offset[n3]) {
                        /*                            printf("%u => %lu\n", rrp->label[n].offset, n3);*/
                        rrp->label[n].n_offset      = n3;
                        rrp->label[n].have_n_offset = 1;
                        break;
                    }
                }
            }
        }
        for (n = 0; n < rrp->mixed_rdatas; n++) {
            for (n2 = 0; n2 < rrp->mixed_rdata[n].labels; n2++) {
                if (!rrp->mixed_rdata[n].label[n2].size && rrp->mixed_rdata[n].label[n2].offset) {
                    for (n3 = 0; n3 < n_offset; n3++) {
                        if (rrp->mixed_rdata[n].label[n2].offset == offset[n3]) {
                            /*                                printf("%u => %lu\n", rrp->mixed_rdata[n].label[n2].offset, n3);*/
                            rrp->mixed_rdata[n].label[n2].n_offset      = n3;
                            rrp->mixed_rdata[n].label[n2].have_n_offset = 1;
                            break;
                        }
                    }
                }
            }
        }
    }
}

void dns_rr_build_rlabel(dns_rr_t* rr_list, size_t count)
{
    dns_rr_t* rrp;
    size_t    rr, n;

    for (rr = 0; rr < count; rr++) {
        rrp = &(rr_list[rr]);

        if (rrp->labels) {
            if (!dns_rlabel_find(rrp->label, rrp->labels, &(rrp->rlabel_idx))) {
                rrp->have_rlabel_idx = 1;
            } else {
                dns_rlabel_add(rrp->label, rrp->labels);
            }
        }

        for (n = 0; n < rrp->mixed_rdatas; n++) {
            if (rrp->mixed_rdata[n].labels) {
                if (!dns_rlabel_find(rrp->mixed_rdata[n].label, rrp->mixed_rdata[n].labels, &(rrp->mixed_rdata[n].rlabel_idx))) {
                    rrp->mixed_rdata[n].have_rlabel_idx = 1;
                } else {
                    dns_rlabel_add(rrp->mixed_rdata[n].label, rrp->mixed_rdata[n].labels);
                }
            }
        }
    }
}

CborError dns_build_rrs(CborEncoder* message, dns_rr_t* rr_list, size_t count)
{
    CborError   cbor_err = CborNoError;
    CborEncoder rrs;
    dns_rr_t*   rr = rr_list;
    size_t      n  = count;

    if (cbor_err == CborNoError)
        cbor_err = cbor_encoder_create_array(message, &rrs, n);
    while (n--) {
        CborEncoder item;
        if (!(rr->have_type && rr->type == 41)) {
            if (rr->have_type && rr->type == last.dns_type) {
                rr->have_type = 0;
            }
            if (rr->have_class && rr->class == last.dns_class) {
                rr->have_class = 0;
            }
            if (rr->have_ttl && rr->ttl == last.dns_ttl) {
                rr->have_ttl = 0;
            }
        }
        if (rr->have_rdlength && rr->have_rdata) {
            rr->have_rdlength = 0;
        }

        rr->bits = rr->have_type
                   | rr->have_class << 1
                   | rr->have_ttl << 2
                   | rr->have_rdlength << 3;
        if (rr->bits && rr->bits != 0xf) {
            rr->have_bits = 1;
        }

        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_create_array(&rrs, &item,
                (rr->is_complete ? 0 : 1) + rr->have_labels
                    + rr->have_bits + rr->have_type + rr->have_class + rr->have_ttl + rr->have_rdlength
                    + rr->have_rdata);
        if (!rr->is_complete) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_boolean(&item, false);
        }
        if (rr->have_labels) {
            if (rr->have_rlabel_idx) {
                if (cbor_err == CborNoError)
                    cbor_err = cbor_encode_negative_int(&item, rr->rlabel_idx);
            } else {
                if (cbor_err == CborNoError)
                    cbor_err = encode_label(&item, rr->label, rr->labels);
            }
        }
        if (rr->have_bits && cbor_err == CborNoError)
            cbor_err = cbor_encode_simple_value(&item, rr->bits);
        if (rr->have_type && cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&item, rr->type);
        if (rr->have_class && cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&item, rr->class);
        if (rr->have_ttl && cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&item, rr->ttl);
        if (rr->have_rdlength && cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&item, rr->rdlength);
        if (rr->have_rdata_index) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&item, rr->rdata_index);
        } else if (rr->have_rdata_rindex) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_negative_int(&item, rr->rdata_rindex);
        } else if (rr->have_mixed_rdata) {
            CborEncoder  rdatas;
            size_t       n2    = rr->mixed_rdatas;
            dns_rdata_t* rdata = rr->mixed_rdata;

            if (cbor_err == CborNoError)
                cbor_err = cbor_encoder_create_array(&item, &rdatas, rr->mixed_rdatas);
            while (n2--) {
                if (rdata->have_labels) {
                    if (rdata->have_rlabel_idx) {
                        if (cbor_err == CborNoError)
                            cbor_err = cbor_encode_negative_int(&rdatas, rdata->rlabel_idx);
                    } else {
                        if (cbor_err == CborNoError)
                            cbor_err = encode_label(&rdatas, rdata->label, rdata->labels);
                    }
                } else if (rdata->have_rdata) {
                    if (cbor_err == CborNoError)
                        cbor_err = cbor_encode_byte_string(&rdatas, rdata->rdata, rdata->rdata_len);
                }

                rdata++;
            }
            if (cbor_err == CborNoError)
                cbor_err = cbor_encoder_close_container_checked(&item, &rdatas);
        } else if (rr->have_rdata && cbor_err == CborNoError)
            cbor_err = cbor_encode_byte_string(&item, rr->rdata, rr->rdlength);
        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_close_container_checked(&rrs, &item);

        if (!(rr->have_type && rr->type == 41)) {
            if (rr->have_type) {
                last.dns_type = rr->type;
            }
            if (rr->have_class) {
                last.dns_class = rr->class;
            }
            if (rr->have_ttl) {
                last.dns_ttl = rr->ttl;
            }
        }
        rr++;
    }
    if (cbor_err == CborNoError)
        cbor_err = cbor_encoder_close_container_checked(message, &rrs);

    return cbor_err;
}

int output_cds(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* pkt_copy, size_t olen, const u_char* payload, size_t payloadlen)
{
    CborEncoder cbor, message;
    CborError   cbor_err = CborNoError;
    ip_header_t ip;
    dns_t       dns;
    uint8_t*    malformed      = 0;
    size_t      malformed_size = 0;
    size_t      dns_parts      = 0;

    if (!payload) {
        return DUMP_CDS_EINVAL;
    }
    if (!payloadlen) {
        return DUMP_CDS_EINVAL;
    }

    if (!cbor_buf) {
        memset(&last, 0, sizeof(last));
        if (!(cbor_buf = calloc(1, cbor_size + message_size))) {
            return DUMP_CDS_ENOMEM;
        }
    }
    if (!cbor_buf_p) {
        cbor_buf_p = cbor_buf;
    }
    if (!message_buf) {
        if (!(message_buf = calloc(1, message_size))) {
            return DUMP_CDS_ENOMEM;
        }
    }
    if (cbor_flushed) {
        dns_rlabel_t* rlabel;
        struct rdata* r;

        cbor_buf_p = cbor_buf;
        while ((rlabel = last.dns_rlabel)) {
            last.dns_rlabel = rlabel->next;
            free(rlabel);
        }
        while ((r = last.rdata)) {
            last.rdata = r->next;
            rdata_free(r);
        }
        memset(&last, 0, sizeof(last));
        if (rdata_tbl) {
            hash_free(rdata_tbl);
            rdata_tbl = 0;
        }

        cbor_encoder_init(&cbor, message_buf, message_size, 0);
        cbor_err = cbor_encoder_create_array(&cbor, &message, 5 + (use_rdata_index ? 3 : 0) + (use_rdata_rindex ? 4 : 0));
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_text_stringz(&message, "CDSv1");
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&message, CDS_OPTION_RLABELS);
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&message, MAX_RLABELS);
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&message, CDS_OPTION_RLABEL_MIN_SIZE);
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&message, MIN_RLABEL_SIZE);
        if (use_rdata_index) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, CDS_OPTION_USE_RDATA_INDEX);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, CDS_OPTION_RDATA_INDEX_MIN_SIZE);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, RDATA_INDEX_MIN_SIZE);
        } else if (use_rdata_rindex) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, CDS_OPTION_RDATA_RINDEX_SIZE);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, RDATA_RINDEX_SIZE);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, CDS_OPTION_RDATA_RINDEX_MIN_SIZE);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, RDATA_RINDEX_MIN_SIZE);
        }
        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_close_container_checked(&cbor, &message);
        if (cbor_err != CborNoError) {
            fprintf(stderr, "cbor error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
            return DUMP_CDS_ECBOR;
        }

        /*        *cbor_buf_p = 0x9f;*/
        /*        cbor_buf_p++;*/

        if ((cbor_size - (cbor_buf_p - cbor_buf)) < cbor_encoder_get_buffer_size(&cbor, message_buf)) {
            return DUMP_CDS_EBUF;
        }
        memcpy(cbor_buf_p, message_buf, cbor_encoder_get_buffer_size(&cbor, message_buf));
        cbor_buf_p += cbor_encoder_get_buffer_size(&cbor, message_buf);

        cbor_flushed = 0;
    }
    if (!rdata_tbl) {
        if (!(rdata_tbl = hash_create(64 * 1024, rdata_hash, rdata_cmp, rdata_free))) {
            return DUMP_CDS_ENOMEM;
        }
    }

    /*
     * IP Header
     */

    memset(&ip, 0, sizeof(ip_header_t));

    /* fill ip */
    if (from.af == AF_INET6) {
        ip.is_v6 = 1;
        memcpy(&(ip.src_addr6), &(from.u.a6), sizeof(struct in6_addr));
        memcpy(&(ip.dest_addr6), &(to.u.a6), sizeof(struct in6_addr));
        ip.src_port6  = sport;
        ip.dest_port6 = dport;
    } else {
        memcpy(&(ip.src_addr4), &(from.u.a4), sizeof(struct in_addr));
        memcpy(&(ip.dest_addr4), &(to.u.a4), sizeof(struct in_addr));
        ip.src_port4  = sport;
        ip.dest_port4 = dport;
    }

    /* deduplicate */
    {
        int         dedup = 0;
        ip_header_t reverse;

        reverse = ip;

        /* check last.ip */
        if (ip.is_v6) {
            if (!memcmp(&(ip.src_addr6), &(last.ip.src_addr6), sizeof(struct in6_addr)))
                dedup++;
            else
                ip.have_src_addr = 1;

            if (!memcmp(&(ip.dest_addr6), &(last.ip.dest_addr6), sizeof(struct in6_addr)))
                dedup++;
            else
                ip.have_dest_addr = 1;

            if (ip.src_port6 == last.ip.src_port6)
                dedup++;
            else
                ip.have_src_port = 1;

            if (ip.dest_port6 == last.ip.dest_port6)
                dedup++;
            else
                ip.have_dest_port = 1;
        } else {
            if (!memcmp(&(ip.src_addr4), &(last.ip.src_addr4), sizeof(struct in_addr)))
                dedup++;
            else
                ip.have_src_addr = 1;

            if (!memcmp(&(ip.dest_addr4), &(last.ip.dest_addr4), sizeof(struct in_addr)))
                dedup++;
            else
                ip.have_dest_addr = 1;

            if (ip.src_port4 == last.ip.src_port4)
                dedup++;
            else
                ip.have_src_port = 1;

            if (ip.dest_port4 == last.ip.dest_port4)
                dedup++;
            else
                ip.have_dest_port = 1;
        }

        /* check reverse last.ip */
        if (ip.is_v6) {
            if (!memcmp(&(ip.src_addr6), &(last.ip.dest_addr6), sizeof(struct in6_addr)))
                dedup--;
            else
                reverse.have_src_addr = 1;

            if (!memcmp(&(ip.dest_addr6), &(last.ip.src_addr6), sizeof(struct in6_addr)))
                dedup--;
            else
                reverse.have_dest_addr = 1;

            if (ip.src_port6 == last.ip.dest_port6)
                dedup--;
            else
                reverse.have_src_port = 1;

            if (ip.dest_port6 == last.ip.src_port6)
                dedup--;
            else
                reverse.have_dest_port = 1;
        } else {
            if (!memcmp(&(ip.src_addr4), &(last.ip.dest_addr4), sizeof(struct in_addr)))
                dedup--;
            else
                reverse.have_src_addr = 1;

            if (!memcmp(&(ip.dest_addr4), &(last.ip.src_addr4), sizeof(struct in_addr)))
                dedup--;
            else
                reverse.have_dest_addr = 1;

            if (ip.src_port4 == last.ip.dest_port4)
                dedup--;
            else
                reverse.have_src_port = 1;

            if (ip.dest_port4 == last.ip.src_port4)
                dedup--;
            else
                reverse.have_dest_port = 1;
        }

        if (dedup < 0) {
            ip            = reverse;
            ip.is_reverse = 1;
            /*fprintf(stderr, "reverse of last ip ");*/
        }
        /*fprintf(stderr, "v6:%d src:%d dest:%d sport:%d dport:%d\n", ip.is_v6, ip.have_src_addr, ip.have_dest_addr, ip.have_src_port, ip.have_dest_port);*/

        ip.bits = ip.is_v6
                  | ip.have_src_addr << 1
                  | ip.have_dest_addr << 2
                  | (ip.have_src_port | ip.have_dest_port) << 3;

        if (ip.is_v6) {
            last.ip.src_addr6  = ip.src_addr6;
            last.ip.dest_addr6 = ip.dest_addr6;
            last.ip.src_port6  = ip.src_port6;
            last.ip.dest_port6 = ip.dest_port6;
        } else {
            last.ip.src_addr4  = ip.src_addr4;
            last.ip.dest_addr4 = ip.dest_addr4;
            last.ip.src_port4  = ip.src_port4;
            last.ip.dest_port4 = ip.dest_port4;
        }
    }

    /*
     * DNS Message
     */

    if (flags & DNSCAP_OUTPUT_ISDNS) {
        uint8_t*  p = (uint8_t*)payload;
        size_t    l = payloadlen, rr, n, n2, n3;
        int       ret;
        dns_rr_t* rrp;

        size_t   n_offset = 0;
        uint16_t offset[256]; /* TODO: Handle offsets better */

        memset(&dns, 0, sizeof(dns));
        ret = parse_dns(&dns, &p, &l);

        if (ret < 0) {
            free_dns(&dns);
            return DUMP_CDS_ENOMEM;
        } else if (ret > 0) {
            malformed      = p;
            malformed_size = l;
        }

        if (dns.have_qdcount && dns.qdcount == dns.questions) {
            dns.have_qdcount = 0;
        }
        if (dns.have_ancount && dns.ancount == dns.answers) {
            dns.have_ancount = 0;
        }
        if (dns.have_nscount && dns.nscount == dns.authorities) {
            dns.have_nscount = 0;
        }
        if (dns.have_arcount && dns.arcount == dns.additionals) {
            dns.have_arcount = 0;
        }

        dns.cnt_bits = dns.have_qdcount
                       | dns.have_ancount << 1
                       | dns.have_nscount << 2
                       | dns.have_arcount << 3;
        if (dns.cnt_bits && dns.cnt_bits != 0xf) {
            dns.have_cnt_bits = 1;
        }

        dns.rr_bits = dns.have_questions
                      | dns.have_answers << 1
                      | dns.have_authorities << 2
                      | dns.have_additionals << 3;
        if (dns.rr_bits && dns.rr_bits != 0xf) {
            dns.have_rr_bits = 1;
        }

        dns_rr_build_offset(dns.question, dns.questions, &offset[0], sizeof(offset), &n_offset, payload);
        dns_rr_build_offset(dns.answer, dns.answers, &offset[0], sizeof(offset), &n_offset, payload);
        dns_rr_build_offset(dns.authority, dns.authorities, &offset[0], sizeof(offset), &n_offset, payload);
        dns_rr_build_offset(dns.additional, dns.additionals, &offset[0], sizeof(offset), &n_offset, payload);

        /*        for (n = 0; n < n_offset; n++) {*/
        /*            printf("%lu: %u\n", n, offset[n]);*/
        /*        }*/

        dns_rr_set_offset(dns.question, dns.questions, &offset[0], n_offset);
        dns_rr_set_offset(dns.answer, dns.answers, &offset[0], n_offset);
        dns_rr_set_offset(dns.authority, dns.authorities, &offset[0], n_offset);
        dns_rr_set_offset(dns.additional, dns.additionals, &offset[0], n_offset);

        dns_rr_build_rlabel(dns.question, dns.questions);
        dns_rr_build_rlabel(dns.answer, dns.answers);
        dns_rr_build_rlabel(dns.authority, dns.authorities);
        dns_rr_build_rlabel(dns.additional, dns.additionals);
    }

    /*
     * CBOR
     */

    cbor_encoder_init(&cbor, message_buf, message_size, 0);
    cbor_err = cbor_encoder_create_array(&cbor, &message,
        /* timestamp */
        1
            /* message bits */
            + 1
            /* ip header */
            + 1 + ip.have_src_addr + ip.have_dest_addr + (ip.have_src_port | ip.have_dest_port)
            /* dns message */
            + dns.have_id + dns.have_raw
            + dns.have_cnt_bits + dns.have_qdcount + dns.have_ancount + dns.have_nscount + dns.have_arcount
            + dns.have_rr_bits + dns.have_questions + dns.have_answers + dns.have_authorities + dns.have_additionals
            + (malformed ? 1 : 0));

    /*
     * Encode timestamp
     */

    {
        CborEncoder timestamp;

        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_create_array(&message, &timestamp, 2);
        if (last.ts.tv_sec && last.ts.tv_sec <= ts.tv_sec) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_negative_int(&timestamp, ts.tv_sec - last.ts.tv_sec);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_int(&timestamp, ts.tv_usec - last.ts.tv_usec);
        } else {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&timestamp, ts.tv_sec);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&timestamp, ts.tv_usec);
        }
        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_close_container_checked(&message, &timestamp);

        last.ts = ts;
    }

    /*
     * Encode message bits
     */

    if (cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message,
            (flags & DNSCAP_OUTPUT_ISDNS ? 1 : 0)
                + (flags & DNSCAP_OUTPUT_ISDNS ? proto == IPPROTO_TCP ? 1 << 1 : 0
                                               : 0)
                + (flags & DNSCAP_OUTPUT_ISFRAG ? 1 << 2 : 0)
                + (malformed ? 1 << 3 : 0));

    /*
     * Encode IP Header
     */

    if (ip.is_reverse) {
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_negative_int(&message, ip.bits);
    } else {
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_uint(&message, ip.bits);
    }

    if (ip.is_v6) {
        if (ip.have_src_addr && cbor_err == CborNoError)
            cbor_err = cbor_encode_byte_string(&message, (uint8_t*)&(ip.src_addr6), sizeof(struct in6_addr));
        if (ip.have_dest_addr && cbor_err == CborNoError)
            cbor_err = cbor_encode_byte_string(&message, (uint8_t*)&(ip.dest_addr6), sizeof(struct in6_addr));
        if (ip.have_src_port && ip.have_dest_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, (ip.dest_port6 << 16) | ip.src_port6);
        } else if (ip.have_src_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, ip.src_port6);
        } else if (ip.have_dest_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_negative_int(&message, ip.dest_port6);
        }
    } else {
        if (ip.have_src_addr && cbor_err == CborNoError)
            cbor_err = cbor_encode_byte_string(&message, (uint8_t*)&(ip.src_addr4), sizeof(struct in_addr));
        if (ip.have_dest_addr && cbor_err == CborNoError)
            cbor_err = cbor_encode_byte_string(&message, (uint8_t*)&(ip.dest_addr4), sizeof(struct in_addr));
        if (ip.have_src_port && ip.have_dest_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, (ip.dest_port4 << 16) | ip.src_port4);
        } else if (ip.have_src_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&message, ip.src_port4);
        } else if (ip.have_dest_port) {
            if (cbor_err == CborNoError)
                cbor_err = cbor_encode_negative_int(&message, ip.dest_port4);
        }
    }

    /*
     * Encode DNS Message
     */
    if (flags & DNSCAP_OUTPUT_ISDNS && !dns.header_is_complete) {
        if (cbor_err == CborNoError)
            cbor_err = cbor_encode_boolean(&message, false);
    }
    if (dns.have_id && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.id);
    if (dns.have_raw && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.raw);
    if (dns.have_cnt_bits && cbor_err == CborNoError)
        cbor_err = cbor_encode_negative_int(&message, dns.cnt_bits);
    if (dns.have_qdcount && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.qdcount);
    if (dns.have_ancount && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.ancount);
    if (dns.have_nscount && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.nscount);
    if (dns.have_arcount && cbor_err == CborNoError)
        cbor_err = cbor_encode_uint(&message, dns.arcount);
    if (dns.have_rr_bits && cbor_err == CborNoError)
        cbor_err = cbor_encode_simple_value(&message, dns.rr_bits);
    if (dns.have_questions) {
        CborEncoder rrs;
        dns_rr_t*   rr = dns.question;
        size_t      n  = dns.questions;

        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_create_array(&message, &rrs, n);
        while (n--) {
            CborEncoder item;

            if (rr->have_type && rr->type == last.dns_type) {
                rr->have_type = 0;
            }
            if (rr->have_class && rr->class == last.dns_class) {
                rr->have_class = 0;
            }

            if (cbor_err == CborNoError)
                cbor_err = cbor_encoder_create_array(&rrs, &item,
                    (rr->is_complete ? 0 : 1) + rr->have_labels + rr->have_type + rr->have_class);
            if (!rr->is_complete) {
                if (cbor_err == CborNoError)
                    cbor_err = cbor_encode_boolean(&item, false);
            }
            if (rr->have_labels) {
                if (rr->have_rlabel_idx) {
                    if (cbor_err == CborNoError)
                        cbor_err = cbor_encode_negative_int(&item, rr->rlabel_idx);
                } else {
                    if (cbor_err == CborNoError)
                        cbor_err = encode_label(&item, rr->label, rr->labels);
                }
            }
            if (rr->have_type && cbor_err == CborNoError)
                cbor_err = cbor_encode_uint(&item, rr->type);
            if (rr->have_class && cbor_err == CborNoError)
                cbor_err = cbor_encode_negative_int(&item, rr->class);
            if (cbor_err == CborNoError)
                cbor_err = cbor_encoder_close_container_checked(&rrs, &item);

            if (rr->have_type) {
                last.dns_type = rr->type;
            }
            if (rr->have_class) {
                last.dns_class = rr->class;
            }

            rr++;
        }
        if (cbor_err == CborNoError)
            cbor_err = cbor_encoder_close_container_checked(&message, &rrs);
    }
    if (dns.have_answers && cbor_err == CborNoError)
        cbor_err = dns_build_rrs(&message, dns.answer, dns.answers);
    if (dns.have_authorities && cbor_err == CborNoError)
        cbor_err = dns_build_rrs(&message, dns.authority, dns.authorities);
    if (dns.have_additionals && cbor_err == CborNoError)
        cbor_err = dns_build_rrs(&message, dns.additional, dns.additionals);

    /*
     * Encode malformed
     */

    if (malformed && cbor_err == CborNoError)
        cbor_err = cbor_encode_byte_string(&message, (uint8_t*)malformed, malformed_size);

    /*
     * Close
     */

    free_dns(&dns);

    if (cbor_err == CborNoError)
        cbor_err = cbor_encoder_close_container_checked(&cbor, &message);
    if (cbor_err != CborNoError) {
        fprintf(stderr, "cbor error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
        return DUMP_CDS_ECBOR;
    }

    /*    if (print_cbor>1)*/
    /*    {*/
    /*        uint8_t* p = message_buf;*/
    /*        size_t s = cbor_encoder_get_buffer_size(&cbor, message_buf);*/

    /*        while (s--) {*/
    /*            printf("%02x", *p++);*/
    /*        }*/
    /*        printf("\n");*/
    /*    }*/

    if (((cbor_size + message_size) - (cbor_buf_p - cbor_buf)) < cbor_encoder_get_buffer_size(&cbor, message_buf)) {
        return DUMP_CDS_EBUF;
    }
    memcpy(cbor_buf_p, message_buf, cbor_encoder_get_buffer_size(&cbor, message_buf));
    cbor_buf_p += cbor_encoder_get_buffer_size(&cbor, message_buf);

    if (cbor_buf_p < (cbor_buf + cbor_size)) {
        return DUMP_CDS_OK;
    }

    cbor_flushed = 1;
    return DUMP_CDS_FLUSH;
}

int dump_cds(FILE* fp)
{
    CborError cbor_err;

    if (!fp) {
        return DUMP_CDS_EINVAL;
    }

    /*    *cbor_buf_p = 0xff;*/
    /*    cbor_buf_p++;*/

    /*    fprintf(stderr, "cds output: %lu bytes\n", cbor_buf_p - cbor_buf);*/

    if (fwrite(cbor_buf, cbor_buf_p - cbor_buf, 1, fp) != 1) {
        return DUMP_CDS_EWRITE;
    }

    return DUMP_CDS_OK;
}

int have_cds_support()
{
    return 1;
}

#else /* HAVE_LIBTINYCBOR */

int cds_set_cbor_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_message_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_max_rlabels(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_min_rlabel_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_use_rdata_index(int use)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_use_rdata_rindex(int use)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_rdata_index_min_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_rdata_rindex_min_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int cds_set_rdata_rindex_size(size_t size)
{
    return DUMP_CDS_ENOSUP;
}

int output_cds(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* pkt_copy, size_t olen, const u_char* payload, size_t payloadlen)
{
    return DUMP_CDS_ENOSUP;
}

int dump_cds()
{
    return DUMP_CDS_ENOSUP;
}

int have_cds_support()
{
    return 0;
}

#endif
