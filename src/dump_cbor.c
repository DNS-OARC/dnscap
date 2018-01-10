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

/*
    DNS-in-JSON
    - generally naming convention
    - compressedNAME.length is there a point here? isn't the length in the
      compressed data itself? Maybe have compressedNAME as just the data
      of the compressed name
    - 2.5 Additional Message Object Members
      - IP stuff:
        - ipProtocol: num
        - sourceIpAddress: string
        - sourcePort: num
        - destinationIpAddress: string
        - destinationPort: num
        or
        - ip: [ ipProtocol, sourceIpAddress, sourcePort, destinationIpAddress, destinationPort ]
      - dateNanoFractions as addition to dateSeconds, specify the fraction of
        nano seconds separatly to have better precision.
*/

#include "config.h"

#include "dump_cbor.h"
#include "dnscap.h"
#include "iaddr.h"

#if HAVE_LIBLDNS && HAVE_LIBTINYCBOR

#include <ldns/ldns.h>
#if HAVE_CBOR_CBOR_H
#include <cbor/cbor.h>
#endif
#if HAVE_CBOR_H
#include <cbor.h>
#endif

static uint8_t* cbor_buf  = 0;
static size_t   cbor_size = 128 * 1024;
/*static size_t cbor_size = 1024;*/
static size_t      cbor_reserve = 64 * 1024;
static CborEncoder cbor_root, cbor_pkts;
/*static cbor_stringref_t *cbor_stringrefs = 0;*/
/*static size_t cbor_stringref_size = 8192;*/
static int cbor_flushed = 1;

int cbor_set_size(size_t size)
{
    if (!size) {
        return DUMP_CBOR_EINVAL;
    }

    cbor_size = size;

    return DUMP_CBOR_OK;
}

int cbor_set_reserve(size_t reserve)
{
    if (!reserve) {
        return DUMP_CBOR_EINVAL;
    }

    cbor_reserve = reserve;

    return DUMP_CBOR_OK;
}

#define append_cbor(func, name, type)                                   \
    CborError func(CborEncoder* encoder, type value, int* should_flush) \
    {                                                                   \
        CborError err;                                                  \
        uint8_t*  ptr = encoder->data.ptr;                              \
        err           = name(encoder, value);                           \
        if (err == CborErrorOutOfMemory && !*should_flush) {            \
            *should_flush     = 1;                                      \
            encoder->data.ptr = ptr;                                    \
            encoder->end      = cbor_buf + cbor_size + cbor_reserve;    \
            err               = name(encoder, value);                   \
        }                                                               \
        return err;                                                     \
    }

static append_cbor(append_cbor_text_stringz, cbor_encode_text_stringz, const char*);
static append_cbor(append_cbor_boolean, cbor_encode_boolean, bool);
static append_cbor(append_cbor_int, cbor_encode_int, int64_t);
static append_cbor(append_cbor_uint, cbor_encode_uint, uint64_t);
static append_cbor(append_cbor_double, cbor_encode_double, double);

static CborError append_cbor_bytes(CborEncoder* encoder, uint8_t* bytes, size_t length, int* should_flush)
{
    CborError err;
    uint8_t*  ptr = encoder->data.ptr;
    err           = cbor_encode_byte_string(encoder, bytes, length);
    if (err == CborErrorOutOfMemory && !*should_flush) {
        *should_flush     = 1;
        encoder->data.ptr = ptr;
        encoder->end      = cbor_buf + cbor_size + cbor_reserve;
        err               = cbor_encode_byte_string(encoder, bytes, length);
    }
    return err;
}

/*CborError append_cbor_text_stringz2(CborEncoder *encoder, const char *value, int *should_flush) {*/
/*    CborError err;*/
/*    uint8_t *ptr = encoder->data.ptr;*/
/*    err = cbor_encode_byte_string(encoder, bytes, length);*/
/*    if (err == CborErrorOutOfMemory && !*should_flush) {*/
/*        *should_flush = 1;*/
/*        encoder->data.ptr = ptr;*/
/*        encoder->end = cbor_buf + cbor_size + cbor_reserve;*/
/*        err = cbor_encode_byte_string(encoder, bytes, length);*/
/*    }*/
/*    return err;*/
/*}*/

#define append_cbor_container(func, name)                                                          \
    CborError func(CborEncoder* encoder, CborEncoder* container, size_t length, int* should_flush) \
    {                                                                                              \
        CborError err;                                                                             \
        uint8_t*  ptr = encoder->data.ptr;                                                         \
        err           = name(encoder, container, length);                                          \
        if (err == CborErrorOutOfMemory && !*should_flush) {                                       \
            *should_flush     = 1;                                                                 \
            encoder->data.ptr = ptr;                                                               \
            encoder->end      = cbor_buf + cbor_size + cbor_reserve;                               \
            err               = name(encoder, container, length);                                  \
        }                                                                                          \
        return err;                                                                                \
    }

static append_cbor_container(append_cbor_array, cbor_encoder_create_array);
static append_cbor_container(append_cbor_map, cbor_encoder_create_map);

static CborError close_cbor_container(CborEncoder* encoder, CborEncoder* container, int* should_flush)
{
    CborError err;
    uint8_t*  ptr = encoder->data.ptr;
    err           = cbor_encoder_close_container_checked(encoder, container);
    if (err == CborErrorOutOfMemory && !*should_flush) {
        *should_flush     = 1;
        encoder->data.ptr = ptr;
        encoder->end      = cbor_buf + cbor_size + cbor_reserve;
        err               = cbor_encoder_close_container_checked(encoder, container);
    }
    return err;
}

static CborError cbor_ldns_rr_list(CborEncoder* encoder, ldns_rr_list* list, size_t count, int* should_flush)
{
    CborError    cbor_err = CborNoError;
    size_t       n;
    ldns_buffer* dname;
    char*        dname_str;

    if (!encoder) {
        return CborErrorInternalError;
    }
    if (!list) {
        return CborErrorInternalError;
    }
    if (!count) {
        return CborErrorInternalError;
    }
    if (!should_flush) {
        return CborErrorInternalError;
    }

    for (n = 0; cbor_err == CborNoError && n < count; n++) {
        CborEncoder  cbor_rr;
        uint8_t*     rdata_bytes;
        ldns_buffer* rdata;
        ldns_rr*     rr = ldns_rr_list_rr(list, n);
        size_t       rd_count;

        if (!rr) {
            return CborErrorInternalError;
        }
        rd_count = ldns_rr_rd_count(rr);

        if (!(dname = ldns_buffer_new(512))) {
            return CborErrorOutOfMemory;
        }
        if (ldns_rdf2buffer_str_dname(dname, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
            ldns_buffer_free(dname);
            return CborErrorInternalError;
        }
        ldns_buffer_write_u8(dname, 0);
        if (!(dname_str = ldns_buffer_export(dname))) {
            ldns_buffer_free(dname);
            return CborErrorOutOfMemory;
        }

        if (cbor_err == CborNoError)
            cbor_err = append_cbor_map(encoder, &cbor_rr, CborIndefiniteLength, should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor_rr, "NAME", should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor_rr, dname_str, should_flush);
        free(dname_str);
        ldns_buffer_free(dname);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor_rr, "CLASS", should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_uint(&cbor_rr, ldns_rr_get_class(rr), should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor_rr, "TYPE", should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_uint(&cbor_rr, ldns_rr_get_type(rr), should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor_rr, "TTL", should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_uint(&cbor_rr, ldns_rr_ttl(rr), should_flush);

        if (rd_count == 1) {
            if (!(rdata = ldns_buffer_new(64 * 1024))) {
                return CborErrorOutOfMemory;
            }
            if (ldns_rdf2buffer_wire(rdata, ldns_rr_rdf(rr, 0)) != LDNS_STATUS_OK) {
                ldns_buffer_free(rdata);
                return CborErrorInternalError;
            }
            if (!(rdata_bytes = ldns_buffer_export(rdata))) {
                ldns_buffer_free(rdata);
                return CborErrorOutOfMemory;
            }

            if (cbor_err == CborNoError)
                cbor_err = append_cbor_text_stringz(&cbor_rr, "RDLENGTH", should_flush);
            if (cbor_err == CborNoError)
                cbor_err = append_cbor_uint(&cbor_rr, ldns_buffer_position(rdata), should_flush);
            if (cbor_err == CborNoError)
                cbor_err = append_cbor_text_stringz(&cbor_rr, "RDATA", should_flush);
            if (cbor_err == CborNoError)
                cbor_err = append_cbor_bytes(&cbor_rr, rdata_bytes, ldns_buffer_position(rdata), should_flush);
            free(rdata_bytes);
            ldns_buffer_free(rdata);
        } else if (rd_count > 1) {
            size_t      n2;
            CborEncoder rr_set;

            if (cbor_err == CborNoError)
                cbor_err = append_cbor_text_stringz(&cbor_rr, "rrSet", should_flush);
            if (cbor_err == CborNoError)
                cbor_err = append_cbor_array(&cbor_rr, &rr_set, CborIndefiniteLength, should_flush);
            for (n2 = 0; n2 < rd_count; n2++) {
                if (!(rdata = ldns_buffer_new(64 * 1024))) {
                    return CborErrorOutOfMemory;
                }
                if (ldns_rdf2buffer_wire(rdata, ldns_rr_rdf(rr, n2)) != LDNS_STATUS_OK) {
                    ldns_buffer_free(rdata);
                    return CborErrorInternalError;
                }
                if (!(rdata_bytes = ldns_buffer_export(rdata))) {
                    ldns_buffer_free(rdata);
                    return CborErrorOutOfMemory;
                }

                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&rr_set, "RDLENGTH", should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_uint(&rr_set, ldns_buffer_position(rdata), should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&rr_set, "RDATA", should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_bytes(&rr_set, rdata_bytes, ldns_buffer_position(rdata), should_flush);
                free(rdata_bytes);
                ldns_buffer_free(rdata);
            }
            if (cbor_err == CborNoError)
                cbor_err = close_cbor_container(&cbor_rr, &rr_set, should_flush);
        }

        if (cbor_err == CborNoError)
            cbor_err = close_cbor_container(encoder, &cbor_rr, should_flush);
    }

    return cbor_err;
}

int output_cbor(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* payload, size_t payloadlen)
{
    ldns_pkt*   pkt = 0;
    ldns_status ldns_rc;

    if (!payload) {
        return DUMP_CBOR_EINVAL;
    }
    if (!payloadlen) {
        return DUMP_CBOR_EINVAL;
    }

    /*    if (!cbor_stringrefs) {*/
    /*        cbor_stringrefs = calloc(1, cbor_stringref_size);*/
    /*    }*/
    if (!cbor_buf) {
        if (!(cbor_buf = calloc(1, cbor_size + cbor_reserve))) {
            return DUMP_CBOR_ENOMEM;
        }
    }
    if (cbor_flushed) {
        CborError cbor_err;

        cbor_encoder_init(&cbor_root, cbor_buf, cbor_size, 0);
        /*        cbor_err = cbor_encode_tag(&cbor_root, 256);*/
        /*        if (cbor_err == CborNoError)*/
        cbor_err = cbor_encoder_create_array(&cbor_root, &cbor_pkts, CborIndefiniteLength);
        if (cbor_err != CborNoError) {
            fprintf(stderr, "cbor init error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
            return DUMP_CBOR_ECBOR;
        }
        cbor_flushed = 0;
    }

    ldns_rc = ldns_wire2pkt(&pkt, payload, payloadlen);

    if (ldns_rc != LDNS_STATUS_OK) {
        fprintf(stderr, "ldns error [%d]: %s\n", ldns_rc, ldns_get_errorstr_by_id(ldns_rc));
        return DUMP_CBOR_ELDNS;
    }
    if (!pkt) {
        return DUMP_CBOR_ELDNS;
    }

    CborEncoder cbor, ip;
    CborError   cbor_err     = CborNoError;
    int         should_flush = 0;

    cbor_err = append_cbor_map(&cbor_pkts, &cbor, CborIndefiniteLength, &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "dateSeconds", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_double(&cbor, (double)ts.tv_sec + ((double)ts.tv_usec / 1000000), &should_flush);
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, "dateNanoFractions", &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_uint(&cbor, ts.tv_usec * 1000, &should_flush);*/

    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "ip", &should_flush);
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_uint(&cbor, proto, &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, "sourceIpAddress", &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, ia_str(from), &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, "sourcePort", &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_uint(&cbor, sport, &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, "destinationIpAddress", &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, ia_str(to), &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_text_stringz(&cbor, "destinationPort", &should_flush);*/
    /*            if (cbor_err == CborNoError) cbor_err = append_cbor_uint(&cbor, dport, &should_flush);*/

    if (cbor_err == CborNoError)
        cbor_err = append_cbor_array(&cbor, &ip, CborIndefiniteLength, &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&ip, proto, &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&ip, ia_str(from), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&ip, sport, &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&ip, ia_str(to), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&ip, dport, &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = close_cbor_container(&cbor, &ip, &should_flush);

    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "ID", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_id(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "QR", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_qr(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "Opcode", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_get_opcode(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "AA", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_aa(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "TC", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_tc(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "RD", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_rd(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "RA", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_ra(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "AD", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_ad(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "CD", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_boolean(&cbor, ldns_pkt_cd(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "RCODE", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_get_rcode(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "QDCOUNT", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_qdcount(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "ANCOUNT", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_ancount(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "NSCOUNT", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_nscount(pkt), &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_text_stringz(&cbor, "ARCOUNT", &should_flush);
    if (cbor_err == CborNoError)
        cbor_err = append_cbor_uint(&cbor, ldns_pkt_arcount(pkt), &should_flush);

    /* questionRRs */

    if (ldns_pkt_qdcount(pkt) > 0) {
        ldns_rr_list* list = ldns_pkt_question(pkt);
        ldns_rr*      rr;
        size_t        n, qdcount = ldns_pkt_qdcount(pkt);
        ldns_buffer*  dname;
        char*         dname_str;

        if (!list) {
            ldns_pkt_free(pkt);
            return DUMP_CBOR_ELDNS;
        }
        rr = ldns_rr_list_rr(list, 0);
        if (!rr) {
            ldns_pkt_free(pkt);
            return DUMP_CBOR_ELDNS;
        }

        if (!(dname = ldns_buffer_new(512))) {
            ldns_pkt_free(pkt);
            return DUMP_CBOR_ENOMEM;
        }
        if (ldns_rdf2buffer_str_dname(dname, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
            ldns_buffer_free(dname);
            ldns_pkt_free(pkt);
            return DUMP_CBOR_ELDNS;
        }
        ldns_buffer_write_u8(dname, 0);
        if (!(dname_str = ldns_buffer_export(dname))) {
            ldns_buffer_free(dname);
            ldns_pkt_free(pkt);
            return DUMP_CBOR_ENOMEM;
        }

        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "QNAME", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, dname_str, &should_flush);
        free(dname_str);
        ldns_buffer_free(dname);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "QCLASS", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_uint(&cbor, ldns_rr_get_class(rr), &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "QTYPE", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_uint(&cbor, ldns_rr_get_type(rr), &should_flush);

        if (qdcount > 1) {
            CborEncoder queries;

            if (cbor_err == CborNoError)
                cbor_err = append_cbor_text_stringz(&cbor, "questionRRs", &should_flush);
            if (cbor_err == CborNoError)
                cbor_err = append_cbor_array(&cbor, &queries, CborIndefiniteLength, &should_flush);
            for (n = 1; cbor_err == CborNoError && n < qdcount; n++) {
                CborEncoder query;

                rr = ldns_rr_list_rr(list, n);
                if (!rr) {
                    ldns_pkt_free(pkt);
                    return DUMP_CBOR_ELDNS;
                }

                if (!(dname = ldns_buffer_new(512))) {
                    ldns_pkt_free(pkt);
                    return DUMP_CBOR_ENOMEM;
                }
                if (ldns_rdf2buffer_str_dname(dname, ldns_rr_owner(rr)) != LDNS_STATUS_OK) {
                    ldns_buffer_free(dname);
                    ldns_pkt_free(pkt);
                    return DUMP_CBOR_ELDNS;
                }
                ldns_buffer_write_u8(dname, 0);
                if (!(dname_str = ldns_buffer_export(dname))) {
                    ldns_buffer_free(dname);
                    ldns_pkt_free(pkt);
                    return DUMP_CBOR_ENOMEM;
                }

                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_map(&queries, &query, CborIndefiniteLength, &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&query, "NAME", &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&query, dname_str, &should_flush);
                free(dname_str);
                ldns_buffer_free(dname);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&query, "CLASS", &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_uint(&query, ldns_rr_get_class(rr), &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_text_stringz(&query, "TYPE", &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = append_cbor_uint(&query, ldns_rr_get_type(rr), &should_flush);
                if (cbor_err == CborNoError)
                    cbor_err = close_cbor_container(&queries, &query, &should_flush);
            }
            if (cbor_err == CborNoError)
                cbor_err = close_cbor_container(&cbor, &queries, &should_flush);
        }
    }

    /* answerRRs */

    if (ldns_pkt_ancount(pkt) > 0) {
        CborEncoder cbor_rrs;

        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "answerRRs", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_array(&cbor, &cbor_rrs, CborIndefiniteLength, &should_flush);
        cbor_ldns_rr_list(&cbor_rrs, ldns_pkt_answer(pkt), ldns_pkt_ancount(pkt), &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = close_cbor_container(&cbor, &cbor_rrs, &should_flush);
    }

    /* authorityRRs */

    if (ldns_pkt_nscount(pkt) > 0) {
        CborEncoder cbor_rrs;

        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "authorityRRs", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_array(&cbor, &cbor_rrs, CborIndefiniteLength, &should_flush);
        cbor_ldns_rr_list(&cbor_rrs, ldns_pkt_authority(pkt), ldns_pkt_nscount(pkt), &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = close_cbor_container(&cbor, &cbor_rrs, &should_flush);
    }

    /* additionalRRs */

    if (ldns_pkt_arcount(pkt) > 0) {
        CborEncoder cbor_rrs;

        if (cbor_err == CborNoError)
            cbor_err = append_cbor_text_stringz(&cbor, "additionalRRs", &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = append_cbor_array(&cbor, &cbor_rrs, CborIndefiniteLength, &should_flush);
        cbor_ldns_rr_list(&cbor_rrs, ldns_pkt_additional(pkt), ldns_pkt_arcount(pkt), &should_flush);
        if (cbor_err == CborNoError)
            cbor_err = close_cbor_container(&cbor, &cbor_rrs, &should_flush);
    }

    ldns_pkt_free(pkt);

    if (cbor_err == CborNoError)
        cbor_err = close_cbor_container(&cbor_pkts, &cbor, &should_flush);

    if (cbor_err != CborNoError) {
        fprintf(stderr, "cbor error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
        return DUMP_CBOR_ECBOR;
    }

    if (should_flush) {
        if ((cbor_err = cbor_encoder_close_container_checked(&cbor_root, &cbor_pkts)) != CborNoError) {
            fprintf(stderr, "cbor error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
            return DUMP_CBOR_ECBOR;
        }

        fprintf(stderr, "cbor output: %lu bytes\n", cbor_encoder_get_buffer_size(&cbor_root, cbor_buf));

        cbor_flushed = 1;
        return DUMP_CBOR_FLUSH;
    }

    return DUMP_CBOR_OK;
}

int dump_cbor(FILE* fp)
{
    CborError cbor_err;

    if (!fp) {
        return DUMP_CBOR_EINVAL;
    }

    if ((cbor_err = cbor_encoder_close_container_checked(&cbor_root, &cbor_pkts)) != CborNoError) {
        fprintf(stderr, "cbor error[%d]: %s\n", cbor_err, cbor_error_string(cbor_err));
        return DUMP_CBOR_ECBOR;
    }

    fprintf(stderr, "cbor output: %lu bytes\n", cbor_encoder_get_buffer_size(&cbor_root, cbor_buf));

    if (fwrite(cbor_buf, cbor_encoder_get_buffer_size(&cbor_root, cbor_buf), 1, fp) != 1) {
        return DUMP_CBOR_EWRITE;
    }

    return DUMP_CBOR_OK;
}

int have_cbor_support()
{
    return 1;
}

#else /* HAVE_LIBLDNS && HAVE_LIBTINYCBOR */

int cbor_set_size(size_t size)
{
    return DUMP_CBOR_ENOSUP;
}

int cbor_set_reserve(size_t reserve)
{
    return DUMP_CBOR_ENOSUP;
}

int output_cbor(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* payload, size_t payloadlen)
{
    return DUMP_CBOR_ENOSUP;
}

int dump_cbor()
{
    return DUMP_CBOR_ENOSUP;
}

int have_cbor_support()
{
    return 0;
}

#endif
