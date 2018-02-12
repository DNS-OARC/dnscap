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

#include "options.h"

#include <string.h>
#include <stdlib.h>

#include <stdio.h>

#define have(a) option_length == (sizeof(a) - 1) && !strncmp(option, a, (sizeof(a) - 1))

int option_parse(options_t* options, const char* option)
{
    const char* argument;
    int         option_length;
    char*       p;
    size_t      s;

    if (!options) {
        return -1;
    }
    if (!option) {
        return -1;
    }

    if (!(argument = strchr(option, '='))) {
        return -2;
    }
    argument++;
    if (!*argument) {
        return -2;
    }
    option_length = argument - option - 1;
    if (option_length < 1) {
        return -2;
    }

    if (have("cbor_chunk_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cbor_chunk_size = s;
            return 0;
        }
    } else if (have("cds_cbor_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_cbor_size = s;
            return 0;
        }
    } else if (have("cds_message_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_message_size = s;
            return 0;
        }
    } else if (have("cds_max_rlabels")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_max_rlabels = s;
            return 0;
        }
    } else if (have("cds_min_rlabel_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_min_rlabel_size = s;
            return 0;
        }
    } else if (have("cds_use_rdata_index")) {
        if (!strcmp(argument, "yes")) {
            options->cds_use_rdata_index = 1;
            return 0;
        }
    } else if (have("cds_rdata_index_min_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_index_min_size = s;
            return 0;
        }
    } else if (have("cds_use_rdata_rindex")) {
        if (!strcmp(argument, "yes")) {
            options->cds_use_rdata_rindex = 1;
            return 0;
        }
    } else if (have("cds_rdata_rindex_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_rindex_size = s;
            return 0;
        }
    } else if (have("cds_rdata_rindex_min_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_rindex_min_size = s;
            return 0;
        }
    } else if (have("dump_format")) {
        if (!strcmp(argument, "pcap")) {
            options->dump_format = pcap;
            return 0;
        } else if (!strcmp(argument, "cbor")) {
            options->dump_format = cbor;
            return 0;
        } else if (!strcmp(argument, "cds")) {
            options->dump_format = cds;
            return 0;
        }
    } else if (have("user")) {
        if (options->user) {
            free(options->user);
        }
        if ((options->user = strdup(argument))) {
            return 0;
        }
    } else if (have("group")) {
        if (options->group) {
            free(options->group);
        }
        if ((options->group = strdup(argument))) {
            return 0;
        }
    } else if (have("pcap_buffer_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->pcap_buffer_size = s;
            return 0;
        }
    } else if (have("use_layers")) {
        if (!strcmp(argument, "yes")) {
            options->use_layers = 1;
            return 0;
        }
    } else if (have("defrag_ipv4")) {
        if (!strcmp(argument, "yes")) {
            options->defrag_ipv4 = 1;
            return 0;
        }
    } else if (have("max_ipv4_fragments")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->max_ipv4_fragments = s;
            return 0;
        }
    } else if (have("max_ipv4_fragments_per_packet")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->max_ipv4_fragments_per_packet = s;
            return 0;
        }
    } else if (have("defrag_ipv6")) {
        if (!strcmp(argument, "yes")) {
            options->defrag_ipv6 = 1;
            return 0;
        }
    } else if (have("max_ipv6_fragments")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->max_ipv6_fragments = s;
            return 0;
        }
    } else if (have("max_ipv6_fragments_per_packet")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->max_ipv6_fragments_per_packet = s;
            return 0;
        }
    } else if (have("parse_ongoing_tcp")) {
        if (!strcmp(argument, "yes")) {
            options->parse_ongoing_tcp = 1;
            return 0;
        }
    } else if (have("allow_reset_tcpstate")) {
        if (!strcmp(argument, "yes")) {
            options->allow_reset_tcpstate = 1;
            return 0;
        }
    } else if (have("reassemble_tcp")) {
        if (!strcmp(argument, "yes")) {
            options->reassemble_tcp = 1;
            return 0;
        }
    } else if (have("reassemble_tcp_faultreset")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->reassemble_tcp_faultreset = s;
            return 0;
        }
    } else if (have("reassemble_tcp_bfbparsedns")) {
        if (!strcmp(argument, "yes")) {
            options->reassemble_tcp_bfbparsedns = 1;
            return 0;
        }
    } else if (have("bpf_hosts_apply_all")) {
        if (!strcmp(argument, "yes")) {
            options->bpf_hosts_apply_all = 1;
            return 0;
        }
    }

    return 1;
}

void options_free(options_t* options)
{
    if (options) {
        if (options->user) {
            free(options->user);
            options->user = 0;
        }
        if (options->group) {
            free(options->group);
            options->group = 0;
        }
    }
}
