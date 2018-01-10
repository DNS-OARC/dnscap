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

#include "pcaps.h"
#include "log.h"
#include "network.h"

#include "pcap-thread/pcap_thread_ext_frag.h"

static void
drop_pkt(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt, const char* name, const int dlt)
{
    mypcap_ptr mypcap = (mypcap_ptr)user;

    pcap_drops++;
    if (mypcap) {
        mypcap->drops++;
    }
}

void print_pcap_thread_error(const char* func, int err)
{
    if (err == PCAP_THREAD_EPCAP) {
        fprintf(stderr, "%s: pcap_thread libpcap error [%d] %s: %s (%s)\n",
            ProgramName,
            pcap_thread_status(&pcap_thread),
            func,
            pcap_statustostr(pcap_thread_status(&pcap_thread)),
            pcap_thread_errbuf(&pcap_thread));
    } else if (err != PCAP_THREAD_OK) {
        fprintf(stderr, "%s: pcap_thread error [%d] %s: %s\n",
            ProgramName,
            err,
            func,
            pcap_thread_strerr(err));
    }
}

void open_pcaps(void)
{
    mypcap_ptr mypcap;
    int        err;

    if ((err = pcap_thread_set_snaplen(&pcap_thread, SNAPLEN)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_snaplen()", err);
        exit(1);
    }
    if ((err = pcap_thread_set_promiscuous(&pcap_thread, promisc)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_promiscuous()", err);
        exit(1);
    }
    if ((err = pcap_thread_set_monitor(&pcap_thread, monitor_mode)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_monitor()", err);
        exit(1);
    }
    if ((err = pcap_thread_set_immediate_mode(&pcap_thread, immediate_mode)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_immediate_mode()", err);
        exit(1);
    }
    if (options.use_layers) {
        if ((err = pcap_thread_set_callback_icmp(&pcap_thread, layer_pkt)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_callback_icmp()", err);
            exit(1);
        }
        if ((err = pcap_thread_set_callback_icmpv6(&pcap_thread, layer_pkt)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_callback_icmpv6()", err);
            exit(1);
        }
        if ((err = pcap_thread_set_callback_udp(&pcap_thread, layer_pkt)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_callback_udp()", err);
            exit(1);
        }
        if ((err = pcap_thread_set_callback_tcp(&pcap_thread, layer_pkt)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_callback_tcp()", err);
            exit(1);
        }

        if ((err = pcap_thread_set_use_layers(&pcap_thread, 1)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_use_layers()", err);
            exit(1);
        }

        if (options.defrag_ipv4) {
            pcap_thread_ext_frag_conf_t frag_conf = PCAP_THREAD_EXT_FRAG_CONF_T_INIT;

            if (options.max_ipv4_fragments > 0 && (err = pcap_thread_ext_frag_conf_set_fragments(&frag_conf, options.max_ipv4_fragments)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_fragments()", err);
                exit(1);
            }
            if (options.max_ipv4_fragments_per_packet > 0 && (err = pcap_thread_ext_frag_conf_set_per_packet(&frag_conf, options.max_ipv4_fragments_per_packet)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_per_packet()", err);
                exit(1);
            }
            if ((err = pcap_thread_set_callback_ipv4_frag(&pcap_thread, pcap_thread_ext_frag_layer_callback(&frag_conf))) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_set_callback_ipv4_frag()", err);
                exit(1);
            }
        }
        if (options.defrag_ipv6) {
            pcap_thread_ext_frag_conf_t frag_conf = PCAP_THREAD_EXT_FRAG_CONF_T_INIT;

            if (options.max_ipv6_fragments > 0 && (err = pcap_thread_ext_frag_conf_set_fragments(&frag_conf, options.max_ipv6_fragments)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_fragments()", err);
                exit(1);
            }
            if (options.max_ipv6_fragments_per_packet > 0 && (err = pcap_thread_ext_frag_conf_set_per_packet(&frag_conf, options.max_ipv6_fragments_per_packet)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_per_packet()", err);
                exit(1);
            }
            if ((err = pcap_thread_set_callback_ipv6_frag(&pcap_thread, pcap_thread_ext_frag_layer_callback(&frag_conf))) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_set_callback_ipv6_frag()", err);
                exit(1);
            }
        }
    } else {
        if ((err = pcap_thread_set_callback(&pcap_thread, dl_pkt)) != PCAP_THREAD_OK) {
            print_pcap_thread_error("pcap_thread_set_callback()", err);
            exit(1);
        }
    }
    if ((err = pcap_thread_set_dropback(&pcap_thread, drop_pkt)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_dropback()", err);
        exit(1);
    }
    if ((err = pcap_thread_set_filter(&pcap_thread, bpft, strlen(bpft))) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_filter()", err);
        exit(1);
    }
    if (options.pcap_buffer_size && (err = pcap_thread_set_buffer_size(&pcap_thread, options.pcap_buffer_size)) != PCAP_THREAD_OK) {
        print_pcap_thread_error("pcap_thread_set_buffer_size()", err);
        exit(1);
    }

    assert(!EMPTY(mypcaps));
    for (mypcap = HEAD(mypcaps);
         mypcap != NULL;
         mypcap = NEXT(mypcap, link)) {
        if (pcap_offline)
            err = pcap_thread_open_offline(&pcap_thread, mypcap->name, (u_char*)mypcap);
        else
            err = pcap_thread_open(&pcap_thread, mypcap->name, (u_char*)mypcap);

        if (err == PCAP_THREAD_EPCAP) {
            fprintf(stderr, "%s: pcap_thread libpcap error [%d]: %s (%s)\n",
                ProgramName,
                pcap_thread_status(&pcap_thread),
                pcap_statustostr(pcap_thread_status(&pcap_thread)),
                pcap_thread_errbuf(&pcap_thread));
            exit(1);
        }
        if (err) {
            fprintf(stderr, "%s: pcap_thread error [%d]: %s\n",
                ProgramName,
                err,
                pcap_thread_strerr(err));
            exit(1);
        }
    }
    pcap_dead = pcap_open_dead(DLT_RAW, SNAPLEN);
}

void poll_pcaps(void)
{
    pcap_thread_run(&pcap_thread);
    main_exit = TRUE;
}

void breakloop_pcaps(void)
{
    pcap_thread_stop(&pcap_thread);
}

void close_pcaps(void)
{
    pcap_thread_close(&pcap_thread);
}

static void stat_callback(u_char* user, const struct pcap_stat* stats, const char* name, int dlt)
{
    mypcap_ptr mypcap;
    for (mypcap = HEAD(mypcaps);
         mypcap != NULL;
         mypcap = NEXT(mypcap, link)) {
        if (!strcmp(name, mypcap->name))
            break;
    }

    if (mypcap) {
        mypcap->ps0 = mypcap->ps1;
        mypcap->ps1 = *stats;
        logerr("%s: %u recv %u drop %u total ptdrop %lu",
            mypcap->name,
            mypcap->ps1.ps_recv - mypcap->ps0.ps_recv,
            mypcap->ps1.ps_drop - mypcap->ps0.ps_drop,
            mypcap->ps1.ps_recv + mypcap->ps1.ps_drop - mypcap->ps0.ps_recv - mypcap->ps0.ps_drop,
            mypcap->drops);
    }
}

void do_pcap_stats()
{
    logerr("total drops: %lu", pcap_drops);
    pcap_thread_stats(&pcap_thread, stat_callback, 0);
}
