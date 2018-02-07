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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "dnscap_common.h"

static logerr_t*   logerr;
static int         opt_f = 0;
static const char* opt_x = 0;

output_t template_output;

void template_usage()
{
    fprintf(stderr,
        "\ntemplate.so options:\n"
        "\t-f         flag option\n"
        "\t-x <arg>   option with argument\n");
}

void template_getopt(int* argc, char** argv[])
{
    /*
     * The "getopt" function will be called from the parent to
     * process plugin options.
     */
    int c;
    while ((c = getopt(*argc, *argv, "fx:")) != EOF) {
        switch (c) {
        case 'f':
            opt_f = 1;
            break;
        case 'x':
            opt_x = strdup(optarg);
            break;
        default:
            template_usage();
            exit(1);
        }
    }
}

int template_start(logerr_t* a_logerr)
{
    /*
     * The "start" function is called once, when the program
     * starts.  It is used to initialize the plugin.  If the
     * plugin wants to write debugging and or error messages,
     * it should save the a_logerr pointer passed from the
     * parent code.
     */
    logerr = a_logerr;
    return 0;
}

void template_stop()
{
    /*
     * The "start" function is called once, when the program
     * is exiting normally.  It might be used to clean up state,
     * free memory, etc.
     */
}

int template_open(my_bpftimeval ts)
{
    /*
     * The "open" function is called at the start of each
     * collection interval, which might be based on a period
     * of time or a number of packets.  In the original code,
     * this is where we opened an output pcap file.
     */
    return 0;
}

int template_close(my_bpftimeval ts)
{
    /*
     * The "close" function is called at the end of each
     * collection interval, which might be based on a period
     * of time or on a number of packets.  In the original code
     * this is where we closed an output pcap file.
     */
    return 0;
}

void template_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    /*
     * Here you can "process" a packet.  The function is named
     * "output" because in the original code this is where
     * packets were outputted.
     *
     * if flags & PCAP_OUTPUT_ISDNS != 0 then payload is the start of a DNS message.
     *
     * if flags & PCAP_OUTPUT_ISFRAG != 0 then the packet is a fragment.
     *
     * if flags & PCAP_OUTPUT_ISLAYER != 0 then the pkt_copy is the same as payload.
     */
}
