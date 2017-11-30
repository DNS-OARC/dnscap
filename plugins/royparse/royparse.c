#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "dnscap_common.h"

#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <pcap.h>

static logerr_t*   logerr;
static const char* opt_q = 0;
static const char* opt_r = 0;

pcap_t*        pd;
pcap_dumper_t* q_out = 0;
static FILE*   r_out = 0;

output_t royparse_output;
ia_str_t royparse_ia_str = 0;

void royparse_usage()
{
    fprintf(stderr,
        "\nroyparse splits a pcap into two streams: queries in pcap format and responses in ASCII format.\n"
        "\nroyparse.so options:\n"
        "\t-q <arg>   query pcap stream output file name (default: no output)\n"
        "\t-r <arg>   royparse output file name (default: stdout)\n");
}

void royparse_extension(int ext, void*arg)
{
    switch (ext) {
    case DNSCAP_EXT_IA_STR:
        royparse_ia_str = (ia_str_t)arg;
        break;
    }
}

void royparse_getopt(int* argc, char** argv[])
{
    int c;

    while ((c = getopt(*argc, *argv, "q:r:")) != EOF) {
        switch (c) {
        case 'q':
            opt_q = strdup(optarg);
            break;
        case 'r':
            opt_r = strdup(optarg);
            break;
        default:
            royparse_usage();
            exit(1);
        }
    }
}

int royparse_start(logerr_t* a_logerr)
{
    logerr = a_logerr;

    if (opt_q) {
        pd    = pcap_open_dead(DLT_RAW, 65535);
        q_out = pcap_dump_open(pd, opt_q);
        if (q_out == 0) {
            logerr("%s: %s\n", opt_q, strerror(errno));
            exit(1);
        }
    }
    if (opt_r) {
        r_out = fopen(opt_r, "w");
        if (r_out == 0) {
            logerr("%s: %s\n", opt_r, strerror(errno));
            exit(1);
        }
    } else {
        r_out = stdout;
    }

    return 0;
}

void royparse_stop()
{
    if (q_out != 0) {
        pcap_close(pd);
        pcap_dump_close(q_out);
    }
    fclose(r_out);
}

int royparse_open(my_bpftimeval ts)
{
    return 0;
}

int royparse_close(my_bpftimeval ts)
{
    return 0;
}

void royparse_normalize(char* str)
{
    /*
     * The "normalize" function converts upper case characters to lower case,
     * and replaces the space and comma characters with a question mark.
     */

    for (; *str; str++) {
        if (('A' <= *str) && (*str <= 'Z')) {
            *str |= 32;
        } else if ((*str == ',') || (*str == ' ')) {
            *str = '?';
        }
    }
}

void royparse_output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, unsigned olen,
    const u_char* payload, unsigned payloadlen)
{
    if (flags & DNSCAP_OUTPUT_ISDNS) {
        int    rrmax;
        ns_msg msg;
        ns_rr  rr;
        ns_initparse(payload, payloadlen, &msg);
        if (ns_msg_getflag(msg, ns_f_qr) != 0 && sport == 53) {
            fprintf(r_out, "%cD_", ns_msg_getflag(msg, ns_f_rd) ? 'R' : 'N');

            switch (ns_msg_getflag(msg, ns_f_opcode)) {
            case ns_o_query:
                fprintf(r_out, "QUERY");
                break;
            case ns_o_notify:
                fprintf(r_out, "NOTIFY");
                break;
            case ns_o_update:
                fprintf(r_out, "UPDATE");
                break;
            default:
                fprintf(r_out, "ELSE");
            }

            fprintf(r_out, "_%u_%cA_", ns_msg_count(msg, ns_s_an) ? 1 : 0, ns_msg_getflag(msg, ns_f_aa) ? 'A' : 'N');

            switch (ns_msg_getflag(msg, ns_f_rcode)) {
            case ns_r_noerror:
                fprintf(r_out, "NOERROR");
                break;
            case ns_r_formerr:
                fprintf(r_out, "FORMERR");
                break;
            case ns_r_nxdomain:
                fprintf(r_out, "NXDOMAIN");
                break;
            case ns_r_notimpl:
                fprintf(r_out, "NOTIMP");
                break;
            case ns_r_refused:
                fprintf(r_out, "REFUSED");
                break;
            case ns_r_notauth:
                fprintf(r_out, "NOTAUTH");
                break;
            default:
                fprintf(r_out, "ELSE");
            }

            fprintf(r_out, " %s,", royparse_ia_str(to));

            if (ns_msg_count(msg, ns_s_qd) > 0) {
                if (ns_parserr(&msg, ns_s_qd, 0, &rr) == 0) {
                    royparse_normalize(ns_rr_name(rr));
                    fprintf(r_out, "%s%s,%u", ns_rr_name(rr), (ns_rr_name(rr)[0] == '.') ? "" : ".", ns_rr_type(rr));
                } else
                    fprintf(r_out, "ERR,ERR");
            } else
                fprintf(r_out, ",");

            fprintf(r_out, ",%ld,%s%s%s%s", ns_msg_size(msg), ns_msg_id(msg) < 256 ? "-L" : "",
                ns_msg_getflag(msg, ns_f_tc) ? "-TC" : "",
                ns_msg_getflag(msg, ns_f_ad) ? "-AD" : "",
                ns_msg_getflag(msg, ns_f_cd) ? "-CD" : "");
            rrmax = ns_msg_count(msg, ns_s_ar);

            while (rrmax > 0) {
                rrmax--;
                ns_parserr(&msg, ns_s_ar, rrmax, &rr);
                if (ns_rr_type(rr) == ns_t_opt) {
                    fprintf(r_out, "-%c", (u_long)ns_rr_ttl(rr) & NS_OPT_DNSSEC_OK ? 'D' : 'E');
                    break;
                }
            }
            fprintf(r_out, "\n");
        } else if (opt_q != 0 && ns_msg_getflag(msg, ns_f_qr) == 0 && dport == 53) {
            struct pcap_pkthdr h;
            memset(&h, 0, sizeof h);
            h.ts  = ts;
            h.len = h.caplen = olen;
            pcap_dump((u_char*)q_out, &h, pkt_copy);
        }
    }
}
