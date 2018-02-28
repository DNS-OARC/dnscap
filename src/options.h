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

#include <sys/types.h>

#include "dump_cds.h"

#ifndef __dnscap_options_h
#define __dnscap_options_h

typedef enum dump_format dump_format_t;
enum dump_format {
    pcap,
    cbor,
    cds
};

/* clang-format off */

#define OPTIONS_T_DEFAULTS { \
    1024 * 1024, \
\
    1024 * 1024, \
    64 * 1024, \
    CDS_DEFAULT_MAX_RLABELS, \
    CDS_DEFAULT_MIN_RLABEL_SIZE, \
    0, \
    CDS_DEFAULT_RDATA_INDEX_MIN_SIZE, \
    0, \
    CDS_DEFAULT_RDATA_RINDEX_SIZE, \
    CDS_DEFAULT_RDATA_RINDEX_MIN_SIZE, \
\
    pcap, \
\
    0, \
    0, \
\
    0, \
\
    0, 0, 0, 0, 0, 0, 0, \
\
    0, 0, 0, 0, 0, \
\
    0 \
}

/* clang-format on */

typedef struct options options_t;
struct options {
    size_t cbor_chunk_size;

    size_t cds_cbor_size;
    size_t cds_message_size;
    size_t cds_max_rlabels;
    size_t cds_min_rlabel_size;
    int    cds_use_rdata_index;
    size_t cds_rdata_index_min_size;
    int    cds_use_rdata_rindex;
    size_t cds_rdata_rindex_size;
    size_t cds_rdata_rindex_min_size;

    dump_format_t dump_format;

    char* user;
    char* group;

    size_t pcap_buffer_size;

    int    use_layers;
    int    defrag_ipv4;
    size_t max_ipv4_fragments;
    size_t max_ipv4_fragments_per_packet;
    int    defrag_ipv6;
    size_t max_ipv6_fragments;
    size_t max_ipv6_fragments_per_packet;

    int    parse_ongoing_tcp;
    int    allow_reset_tcpstate;
    int    reassemble_tcp;
    size_t reassemble_tcp_faultreset;
    int    reassemble_tcp_bfbparsedns;

    int bpf_hosts_apply_all;
};

int option_parse(options_t* options, const char* option);
void options_free(options_t* options);

#endif /* __dnscap_options_h */
