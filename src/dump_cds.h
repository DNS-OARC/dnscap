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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __dnscap_dump_cds_h
#define __dnscap_dump_cds_h

#define DUMP_CDS_OK 0
#define DUMP_CDS_EINVAL 1
#define DUMP_CDS_ENOMEM 2
#define DUMP_CDS_ECBOR 3
#define DUMP_CDS_ELDNS 4
#define DUMP_CDS_EWRITE 5
#define DUMP_CDS_FLUSH 6
#define DUMP_CDS_ENOSUP 7
#define DUMP_CDS_EBUF 8

#define CDS_OPTION_RLABELS 0
#define CDS_OPTION_RLABEL_MIN_SIZE 1
#define CDS_OPTION_RDATA_RINDEX_SIZE 2
#define CDS_OPTION_RDATA_RINDEX_MIN_SIZE 3
#define CDS_OPTION_USE_RDATA_INDEX 4
#define CDS_OPTION_RDATA_INDEX_MIN_SIZE 5

#define CDS_DEFAULT_MAX_RLABELS 255
#define CDS_DEFAULT_MIN_RLABEL_SIZE 3
#define CDS_DEFAULT_RDATA_INDEX_MIN_SIZE 5
#define CDS_DEFAULT_RDATA_RINDEX_SIZE 255
#define CDS_DEFAULT_RDATA_RINDEX_MIN_SIZE 5

typedef struct ip_header ip_header_t;
struct ip_header {
    unsigned short is_v6 : 1;
    unsigned short is_reverse : 1;
    unsigned short have_src_addr : 1;
    unsigned short have_src_port : 1;
    unsigned short have_dest_addr : 1;
    unsigned short have_dest_port : 1;

    uint8_t         bits;
    struct in_addr  src_addr4;
    uint16_t        src_port4;
    struct in6_addr src_addr6;
    uint16_t        src_port6;
    struct in_addr  dest_addr4;
    uint16_t        dest_port4;
    struct in6_addr dest_addr6;
    uint16_t        dest_port6;
};

typedef struct dns_label dns_label_t;
struct dns_label {
    unsigned short is_complete : 1;
    unsigned short have_size : 1;
    unsigned short have_extension_bits : 1;
    unsigned short have_offset : 1;
    unsigned short have_label : 1;
    unsigned short have_n_offset : 1;

    uint8_t  size;
    uint8_t  extension_bits;
    uint16_t offset;
    uint8_t* offset_p;
    uint8_t* label;
    size_t   n_offset;
};

#define CDS_RLABEL_LABEL_T_LABEL 64

typedef struct dns_rlabel_label dns_rlabel_label_t;
struct dns_rlabel_label {
    unsigned short have_n_offset : 1;

    uint8_t size;
    uint8_t label[CDS_RLABEL_LABEL_T_LABEL];
    size_t  n_offset;
};

#define CDS_RLABEL_T_LABELS 256

typedef struct dns_rlabel dns_rlabel_t;
struct dns_rlabel {
    dns_rlabel_t* next;
    dns_rlabel_t* prev;

    uint8_t            labels;
    dns_rlabel_label_t label[CDS_RLABEL_T_LABELS];
};

typedef struct dns_rdata dns_rdata_t;
struct dns_rdata {
    unsigned short is_complete : 1;
    unsigned short have_labels : 1;
    unsigned short have_rlabel_idx : 1;
    unsigned short have_rdata : 1;

    size_t       rdata_len;
    uint8_t*     rdata;
    size_t       labels;
    dns_label_t* label;
    size_t       rlabel_idx;
};

typedef struct dns_rr dns_rr_t;
struct dns_rr {
    unsigned short is_complete : 1;
    unsigned short have_labels : 1;
    unsigned short have_rlabel_idx : 1;
    unsigned short have_bits : 1;
    unsigned short have_type : 1;
    unsigned short have_class : 1;
    unsigned short have_ttl : 1;
    unsigned short have_rdlength : 1;
    unsigned short have_rdata : 1;
    unsigned short have_mixed_rdata : 1;
    unsigned short have_rdata_index : 1;
    unsigned short have_rdata_rindex : 1;

    size_t       labels;
    dns_label_t* label;
    size_t       rlabel_idx;
    uint8_t      bits;
    uint16_t     type;
    uint16_t class;
    uint32_t     ttl;
    uint16_t     rdlength;
    uint8_t*     rdata;
    size_t       mixed_rdatas;
    dns_rdata_t* mixed_rdata;
    size_t       rdata_index;
    size_t       rdata_rindex;
};

typedef struct dns dns_t;
struct dns {
    unsigned short header_is_complete : 1;
    unsigned short have_id : 1;
    unsigned short have_raw : 1;
    unsigned short have_cnt_bits : 1;
    unsigned short have_qdcount : 1;
    unsigned short have_ancount : 1;
    unsigned short have_nscount : 1;
    unsigned short have_arcount : 1;
    unsigned short have_rr_bits : 1;
    unsigned short have_questions : 1;
    unsigned short have_answers : 1;
    unsigned short have_authorities : 1;
    unsigned short have_additionals : 1;

    int       id;
    uint16_t  raw;
    uint8_t   cnt_bits;
    uint16_t  qdcount;
    uint16_t  ancount;
    uint16_t  nscount;
    uint16_t  arcount;
    uint8_t   rr_bits;
    size_t    questions;
    dns_rr_t* question;
    size_t    answers;
    dns_rr_t* answer;
    size_t    authorities;
    dns_rr_t* authority;
    size_t    additionals;
    dns_rr_t* additional;
};

int cds_set_cbor_size(size_t size);
int cds_set_message_size(size_t size);
int cds_set_max_rlabels(size_t size);
int cds_set_min_rlabel_size(size_t size);
int cds_set_use_rdata_index(int use);
int cds_set_use_rdata_rindex(int use);
int cds_set_rdata_index_min_size(size_t size);
int cds_set_rdata_rindex_min_size(size_t size);
int cds_set_rdata_rindex_size(size_t size);
int output_cds(iaddr from, iaddr to, uint8_t proto, unsigned flags, unsigned sport, unsigned dport, my_bpftimeval ts, const u_char* pkt_copy, size_t olen, const u_char* payload, size_t payloadlen);
int dump_cds();
int have_cds_support();

#endif /* __dnscap_dump_cds_h */
