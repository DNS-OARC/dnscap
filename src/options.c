/*
 * Copyright (c) 2016, OARC, Inc.
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

int option_parse(options_t * options, const char * option) {
    const char * argument;
    int option_length;
    char * p;
    size_t s;

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
    }
    else if (have("cds_cbor_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_cbor_size = s;
            return 0;
        }
    }
    else if (have("cds_message_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_message_size = s;
            return 0;
        }
    }
    else if (have("cds_max_rlabels")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_max_rlabels = s;
            return 0;
        }
    }
    else if (have("cds_min_rlabel_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_min_rlabel_size = s;
            return 0;
        }
    }
    else if (have("cds_use_rdata_index")) {
        if (!strcmp(argument, "yes")) {
            options->cds_use_rdata_index = 1;
            return 0;
        }
    }
    else if (have("cds_rdata_index_min_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_index_min_size = s;
            return 0;
        }
    }
    else if (have("cds_use_rdata_rindex")) {
        if (!strcmp(argument, "yes")) {
            options->cds_use_rdata_rindex = 1;
            return 0;
        }
    }
    else if (have("cds_rdata_rindex_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_rindex_size = s;
            return 0;
        }
    }
    else if (have("cds_rdata_rindex_min_size")) {
        s = strtoul(argument, &p, 0);
        if (p && !*p && s > 0) {
            options->cds_rdata_rindex_min_size = s;
            return 0;
        }
    }
    else if (have("dump_format")) {
        if (!strcmp(argument, "pcap")) {
            options->dump_format = pcap;
            return 0;
        }
        else if (!strcmp(argument, "cbor")) {
            options->dump_format = cbor;
            return 0;
        }
        else if (!strcmp(argument, "cds")) {
            options->dump_format = cds;
            return 0;
        }
    }
    else if (have("user")) {
        if (options->user) {
            free(options->user);
        }
        if ((options->user = strdup(argument))) {
            return 0;
        }
    }
    else if (have("group")) {
        if (options->group) {
            free(options->group);
        }
        if ((options->group = strdup(argument))) {
            return 0;
        }
    }

    return 1;
}

void options_free(options_t * options) {
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
