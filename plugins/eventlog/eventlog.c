/* eventlog.c
 *
 * Byron Darrah - May 20, 2020
 * Version 1.0
 *
 * This is a plugin for dnscap, based on the txtout plugin.
 *
 * This plugin generates one line of output for each packet, with a human-
 * readable timestamp, and includes the results of A and AAAA queries (which
 * is either a list of IP addresses, or an NXDOMAIN flag).
 *
 * Below is the original copyright notice from txtout.c.
 */
/*
 * Copyright (c) 2016-2020, OARC, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "dnscap_common.h"

static logerr_t* logerr;
static char*     opt_o = NULL;
static int       opt_s = 0;
static FILE*     out   = 0;
static int       opt_t = 0;
static char*     opt_n = NULL;

output_t eventlog_output;
void     eventlog_output_ipbytes(unsigned int len, const unsigned char *data);

void eventlog_usage()
{
    fprintf(stderr,
        "\neventlog.so options:\n"
        "   -h         print these instructions and exit\n"
        "   -o <arg>   output file name\n"
        "   -s         short output, only QTYPE/QNAME for IN\n"
        "   -t         prefix event messages with DNS packet timestamp\n"
        "   -n <arg>   include name with each event message\n\n"
        "Produces a line of text per packet suitable for event logging,\n"
        "including IP addresses from query responses.\n");
}

void eventlog_getopt(int* argc, char** argv[])
{
    /*
     * The "getopt" function will be called from the parent to
     * process plugin options.
     */
    int c;
    while ((c = getopt(*argc, *argv, "hso:tn:")) != EOF) {
        switch (c) {
        case 'h':
            eventlog_usage();
            exit(1);
            break;
        case 'o':
            if (opt_o)
                free(opt_o);
            opt_o = strdup(optarg);
            break;
        case 's':
            opt_s = 1;
            break;
        case 't':
            opt_t = 1;
            break;
        case 'n':
            opt_n = strdup(optarg);
            break;
        default:
            eventlog_usage();
            exit(1);
        }
    }
}

int eventlog_start(logerr_t* a_logerr)
{
    /*
     * The "start" function is called once, when the program
     * starts.  It is used to initialize the plugin.  If the
     * plugin wants to write debugging and or error messages,
     * it should save the a_logerr pointer passed from the
     * parent code.
     */
    logerr = a_logerr;
    if (opt_o) {
        out = fopen(opt_o, "a");
        if (0 == out) {
            logerr("%s: %s\n", opt_o, strerror(errno));
            exit(1);
        }
    } else {
        out = stdout;
    }
    setbuf(out, 0);

    if (opt_t) {
      time_t curtime;
      char time_text[25];
      curtime = time(NULL);
      if(strftime(time_text, 25, "%G %m/%d %T", localtime(&curtime)) > 0) {
        fprintf(out, "%s ", time_text);
      } else {
        fprintf(out, "**ERROR reading time** ");
      }
    }
    if (opt_n) {
      fprintf(out, "%s ", opt_n);
    }
    fprintf(out, "DNS event logging started.\n");

   return 0;
}

void eventlog_stop()
{
    /*
     * The "start" function is called once, when the program
     * is exiting normally.  It might be used to clean up state,
     * free memory, etc.
     */
    if (out != stdout)
        fclose(out);
}

int eventlog_open(my_bpftimeval ts)
{
    /*
     * The "open" function is called at the start of each
     * collection interval, which might be based on a period
     * of time or a number of packets.  In the original code,
     * this is where we opened an output pcap file.
     */
    return 0;
}

int eventlog_close(my_bpftimeval ts)
{
    /*
     * The "close" function is called at the end of each
     * collection interval, which might be based on a period
     * of time or on a number of packets.  In the original code
     * this is where we closed an output pcap file.
     */
    return 0;
}

ia_str_t           ia_str           = 0;
tcpstate_getcurr_t tcpstate_getcurr = 0;
tcpstate_reset_t   tcpstate_reset   = 0;

void eventlog_extension(int ext, void* arg)
{
    switch (ext) {
    case DNSCAP_EXT_IA_STR:
        ia_str = (ia_str_t)arg;
        break;
    case DNSCAP_EXT_TCPSTATE_GETCURR:
        tcpstate_getcurr = (tcpstate_getcurr_t)arg;
        break;
    case DNSCAP_EXT_TCPSTATE_RESET:
        tcpstate_reset = (tcpstate_reset_t)arg;
        break;
    }
}

void eventlog_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, unsigned olen,
    const u_char* payload, unsigned payloadlen)
{

    /* Do not output anything if there is no DNS info to report. */
    if ( !(flags & DNSCAP_OUTPUT_ISDNS) ) {
      return;
    }
    ns_msg msg;
    if (ns_initparse(payload, payloadlen, &msg) < 0) {
        if (tcpstate_getcurr && tcpstate_reset)
            tcpstate_reset(tcpstate_getcurr(), "");
        return;
    }

    /*
     * Output the packet timestamp
     */
    if (opt_t) {
        char time_text[25];
        if(strftime(time_text, 25, "%G %m/%d %T", localtime(&ts.tv_sec)) > 0) {
          fprintf(out, "%s ", time_text);
        } else {
          fprintf(out, "**ERROR reading packet time** ");
        }
    }
    if (opt_n) {
        fprintf(out, "%s ", opt_n);
    }

    /*
     * Short output, only print QTYPE and QNAME for IN records
     */
    if (opt_s) {
        int    qdcount, err = 0;
        ns_rr  rr;
        qdcount = ns_msg_count(msg, ns_s_qd);

        if (qdcount > 0 && 0 == (err = ns_parserr(&msg, ns_s_qd, 0, &rr)) && ns_rr_class(rr) == 1) {
            fprintf(out, "%s %s\n",
                p_type(ns_rr_type(rr)),
                ns_rr_name(rr));
        }
        if (err < 0) {
            if (tcpstate_getcurr && tcpstate_reset)
                tcpstate_reset(tcpstate_getcurr(), "");
        }
        return;
    }

    /*
     * IP Stuff
     */
    fprintf(out, "src=%s spt=%u ", ia_str(from), sport);
    fprintf(out, "dst=%s dpt=%u ", ia_str(to), dport);
    switch(proto) {
       case 17:
          fprintf(out, "proto=UDP");
          break;
       case 6:
          fprintf(out, "proto=TCP");
          break;
       default:
          fprintf(out, "proto=%hhu", proto);
          break;
    }
    
    int    rrnum, ancount, qdcount, err = 0;
    ns_rr  rr;
    char  *delim;

    /*
     * DNS Header
     */
    fprintf(out, " mid=%u", ns_msg_id(msg));
    fprintf(out, " op=%u", ns_msg_getflag(msg, ns_f_opcode));
    fprintf(out, " fl=|");
    if (ns_msg_getflag(msg, ns_f_qr))
        fprintf(out, "QR|");
    if (ns_msg_getflag(msg, ns_f_aa))
        fprintf(out, "AA|");
    if (ns_msg_getflag(msg, ns_f_tc))
        fprintf(out, "TC|");
    if (ns_msg_getflag(msg, ns_f_rd))
        fprintf(out, "RD|");
    if (ns_msg_getflag(msg, ns_f_ra))
        fprintf(out, "RA|");
    if (ns_msg_getflag(msg, ns_f_ad))
        fprintf(out, "AD|");
    if (ns_msg_getflag(msg, ns_f_cd))
        fprintf(out, "CD|");
    switch(ns_msg_getflag(msg, ns_f_rcode)) {
        case ns_r_noerror:
          fprintf(out, " rc=OK");
          break;
        case ns_r_nxdomain:
          fprintf(out, " rc=NXDOMAIN");
          break;
        case ns_r_servfail:
          fprintf(out, " rc=SRVFAIL");
          break;
        default:
          fprintf(out, " rc=%u", ns_msg_getflag(msg, ns_f_rcode));
          break;
    }

    qdcount = ns_msg_count(msg, ns_s_qd);
    if (qdcount > 0 && 0 == (err = ns_parserr(&msg, ns_s_qd, 0, &rr))) {
        fprintf(out, " cl=%s tp=%s name=%s",
            p_class(ns_rr_class(rr)),
            p_type(ns_rr_type(rr)),
            ns_rr_name(rr));
    }
    if (err < 0) {
        fprintf(out, " **ERROR parsing response record**\n");
        if (tcpstate_getcurr && tcpstate_reset)
            tcpstate_reset(tcpstate_getcurr(), "");
        return;
    }

    /* output the query answers */
    delim = " ans=";
    for(rrnum = 0; rrnum < ns_msg_count(msg, ns_s_an); rrnum++) {
        if (0 == (err = ns_parserr(&msg, ns_s_an, rrnum, &rr))) {
          /* If the answer is an IP address, output it. */
            if((0 == strncmp(p_type(ns_rr_type(rr)), "A", 2)) ||
               (0 == strncmp(p_type(ns_rr_type(rr)), "AAAA", 5))) {
                fprintf(out, "%s", delim);
                delim=", ";
                eventlog_output_ipbytes(ns_rr_rdlen(rr), ns_rr_rdata(rr));
            }
        }
        if (err < 0) {
            fprintf(out, " **ERROR parsing response record**\n");
            if (tcpstate_getcurr && tcpstate_reset)
                tcpstate_reset(tcpstate_getcurr(), "");
            return;
        }
    }

    /*
     * Done
     */
    fprintf(out, "\n");
}

void eventlog_output_ipbytes(unsigned int len, const unsigned char *data) {
  
  /* If there are 4 bytes, print them as an IPv4 address. */
  if (len == 4) {
    fprintf(out, "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
  }

  /* If there are 16 bytes, print them as an IPv6 address. */
  else if (len == 16) {
  /* If there are 16 bytes, print them as an IPv6 address. */
    fprintf(out, "%x:%x:%x:%x:%x:%x:%x:%x",
            ((unsigned int) data[0]) <<8 | data[1],
            ((unsigned int) data[2]) <<8 | data[3],
            ((unsigned int) data[4]) <<8 | data[5],
            ((unsigned int) data[6]) <<8 | data[7],
            ((unsigned int) data[8]) <<8 | data[9],
            ((unsigned int) data[10])<<8 | data[11],
            ((unsigned int) data[12])<<8 | data[13],
            ((unsigned int) data[14])<<8 | data[15]);
  }
}
