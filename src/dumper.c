/*
 * Copyright (c) 2016-2025 OARC, Inc.
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

#include "dumper.h"
#include "iaddr.h"
#include "log.h"
#include "pcaps.h"
#include "args.h"

#include <zlib.h>

static u_char*  _pkt;
static unsigned _olen;

void set_output_pkt(u_char* pkt, const unsigned olen)
{
    _pkt  = pkt;
    _olen = olen;
}

/*
 * when flags & DNSCAP_OUTPUT_ISDNS, payload points to a DNS packet
 */
void output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    u_char* pkt_copy, const unsigned olen,
    u_char* payload, const unsigned payloadlen)
{
    struct plugin* p;

    _pkt  = pkt_copy;
    _olen = olen;

    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        if (p->filter && (*p->filter)(descr, &from, &to, proto, flags, sport, dport, ts, _pkt, _olen, payload, payloadlen)) {
            if (dumptrace >= 3) {
                fprintf(stderr, "filtered: capturedbytes=%zu, proto=%d, isfrag=%s, isdns=%s, olen=%u, payloadlen=%u\n",
                    capturedbytes,
                    proto,
                    flags & DNSCAP_OUTPUT_ISFRAG ? "yes" : "no",
                    flags & DNSCAP_OUTPUT_ISDNS ? "yes" : "no",
                    olen,
                    payloadlen);
            }
            return;
        }
    }

    msgcount++;
    capturedbytes += olen;
    // TODO: += olen is incorrect when receiving multiple DNS messages in a single packet, such as TCP

    if (dumptrace >= 3) {
        fprintf(stderr, "output: capturedbytes=%zu, proto=%d, isfrag=%s, isdns=%s, olen=%u, payloadlen=%u\n",
            capturedbytes,
            proto,
            flags & DNSCAP_OUTPUT_ISFRAG ? "yes" : "no",
            flags & DNSCAP_OUTPUT_ISDNS ? "yes" : "no",
            olen,
            payloadlen);
    }

    /* Output stage. */
    if (preso) {
        fputs(descr, stderr);
        if (flags & DNSCAP_OUTPUT_ISFRAG) {
            fprintf(stderr, ";: [%s] ", ia_str(from));
            fprintf(stderr, "-> [%s] (frag)\n", ia_str(to));
        } else {
            fprintf(stderr, "\t[%s].%u ", ia_str(from), sport);
            fprintf(stderr, "[%s].%u ", ia_str(to), dport);
            if ((flags & DNSCAP_OUTPUT_ISDNS) && payload)
                dump_dns(payload, payloadlen, stderr, "\\\n\t");
        }
        putc('\n', stderr);
    }
    if (dump_type != nowhere) {
        if (options.dump_format == pcap) {
            if ((options.use_layers || options.reassemble_tcp) && _pkt == pkt_copy)
                usage("use_layers or reassemble_tcp with PCAP output is not supported unless used with plugins that rewrites packets");

            struct pcap_pkthdr h;

            memset(&h, 0, sizeof h);
            h.ts  = ts;
            h.len = h.caplen = _olen;
            pcap_dump((u_char*)dumper, &h, _pkt);
            if (flush)
                pcap_dump_flush(dumper);
        } else if (options.dump_format == cbor && (flags & DNSCAP_OUTPUT_ISDNS) && payload) {
            int ret = output_cbor(from, to, proto, flags, sport, dport, ts, payload, payloadlen);

            if (ret == DUMP_CBOR_FLUSH) {
                if (dumper_close(ts)) {
                    fprintf(stderr, "%s: dumper_close() failed\n", ProgramName);
                    exit(1);
                }
                if (dumper_open(ts)) {
                    fprintf(stderr, "%s: dumper_open() failed\n", ProgramName);
                    exit(1);
                }
            } else if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        } else if (options.dump_format == cds) {
            int ret = output_cds(from, to, proto, flags, sport, dport, ts, _pkt, _olen, payload, payloadlen);

            if (ret == DUMP_CDS_FLUSH) {
                if (dumper_close(ts)) {
                    fprintf(stderr, "%s: dumper_close() failed\n", ProgramName);
                    exit(1);
                }
                if (dumper_open(ts)) {
                    fprintf(stderr, "%s: dumper_open() failed\n", ProgramName);
                    exit(1);
                }
            } else if (ret != DUMP_CDS_OK) {
                fprintf(stderr, "%s: output to cds failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        } else if (options.dump_format == tcpdns) {
            if ((flags & DNSCAP_OUTPUT_ISDNS) && payload && payloadlen > 0) {
                uint16_t len = htons(payloadlen);
                if (fwrite(&len, 1, 2, dumper_fp) != 2
                    || fwrite(payload, 1, payloadlen, dumper_fp) != payloadlen) {
                    fprintf(stderr, "%s: output to tcpdns failed: %s\n", ProgramName, strerror(errno));
                    exit(1);
                }

                // readjust captured bytes
                capturedbytes -= olen;
                capturedbytes += 2 + payloadlen;
            } else {
                // readjust msgcount
                msgcount--;
            }
        }
    }
    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link))
        if (p->output)
            (*p->output)(descr, from, to, proto, flags, sport, dport, ts, _pkt, _olen, payload, payloadlen);
    return;
}

int dumper_open(my_bpftimeval ts)
{
    const char*    t = NULL;
    struct plugin* p;

    assert(dump_state == dumper_closed);

    while (ts.tv_usec >= MILLION) {
        ts.tv_sec++;
        ts.tv_usec -= MILLION;
    }
    if (limit_seconds != 0U)
        next_interval = ts.tv_sec
                        - (ts.tv_sec % limit_seconds)
                        + limit_seconds;

    if (dump_type == to_stdout) {
        t = "-";
    } else if (dump_type == to_file) {
        char      sbuf[64];
        struct tm tm;

        gmtime_r((time_t*)&ts.tv_sec, &tm);
        strftime(sbuf, 64, "%Y%m%d.%H%M%S", &tm);
        if (asprintf(&dumpname, "%s.%s.%06" PRI_tv_usec "%s",
                dump_base, sbuf,
                ts.tv_usec, dump_suffix ? dump_suffix : "")
                < 0
            || asprintf(&dumpnamepart, "%s.part", dumpname) < 0) {
            logerr("asprintf: %s", strerror(errno));
            return (TRUE);
        }
        t = dumpnamepart;
    }
    if (NULL != t) {
        if (options.dump_format == pcap) {
            dumper = dnscap_pcap_dump_open(pcap_dead, t);
            if (dumper == NULL) {
                logerr("pcap dump open: %s",
                    pcap_geterr(pcap_dead));
                return (TRUE);
            }
        } else if (options.dump_format == tcpdns) {
            if (wantgzip) {
                dnscap_dump_open_gz(t, &dumper_fp);
            } else {
                if (!strncmp(t, "-", 1)) {
                    dumper_fp = fdopen(1, "w");
                } else {
                    dumper_fp = fopen(t, "w");
                }
            }
            if (dumper_fp == NULL) {
                logerr("dump fopen: %s", strerror(errno));
                return (TRUE);
            }
        }
    }
    dumpstart = ts.tv_sec;
    if (limit_seconds != 0U) {
        struct timeval now;
        u_int          seconds;
        time_t         targ;

        gettimeofday(&now, NULL);
        while (now.tv_usec >= MILLION) {
            now.tv_sec++;
            now.tv_usec -= MILLION;
        }
        targ = (((now.tv_sec + (limit_seconds / 2))
                    / limit_seconds)
                   + 1)
               * limit_seconds;
        assert(targ > now.tv_sec);
        seconds = targ - now.tv_sec;
        if (next_interval == 0) {
            alarm(seconds);
            alarm_set = TRUE;
        }
    }
    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        int x;
        if (!p->open)
            continue;
        x = (*p->open)(ts);
        if (0 == x)
            continue;
        logerr("%s_open returned %d", p->name, x);
    }
    dump_state = dumper_opened;
    return (FALSE);
}

int dumper_close(my_bpftimeval ts)
{
    int            ret = FALSE;
    struct plugin* p;

    assert(dump_state == dumper_opened);

    if (print_pcap_stats)
        do_pcap_stats();

    if (alarm_set) {
        alarm(0);
        alarm_set = FALSE;
    }

    if (options.dump_format == pcap) {
        if (dumper) {
            pcap_dump_close(dumper);
            dumper = FALSE;
        }
    } else if (options.dump_format == cbor) {
        if (dump_type == to_stdout) {
            ret = dump_cbor(stdout);

            if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        } else if (dump_type == to_file) {
            FILE* fp;

            if (!(fp = fopen(dumpnamepart, "w"))) {
                fprintf(stderr, "%s: fopen(%s) failed: %s\n", ProgramName, dumpnamepart, strerror(errno));
                exit(1);
            }
            ret = dump_cbor(fp);
            fclose(fp);
            if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        }
    } else if (options.dump_format == cds) {
        if (dump_type == to_stdout) {
            ret = dump_cds(stdout);

            if (ret != DUMP_CDS_OK) {
                fprintf(stderr, "%s: output to cds failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        } else if (dump_type == to_file) {
            FILE* fp;

            if (!(fp = fopen(dumpnamepart, "w"))) {
                fprintf(stderr, "%s: fopen(%s) failed: %s\n", ProgramName, dumpnamepart, strerror(errno));
                exit(1);
            }
            ret = dump_cds(fp);
            fclose(fp);
            if (ret != DUMP_CDS_OK) {
                fprintf(stderr, "%s: output to cds failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        }
    } else if (options.dump_format == tcpdns) {
        if (dumper_fp) {
            fclose(dumper_fp);
            dumper_fp = 0;
        }
    }

    if (dump_type == to_stdout) {
        assert(dumpname == NULL);
        assert(dumpnamepart == NULL);
        if (dumptrace >= 1)
            fprintf(stderr, "%s: breaking\n", ProgramName);
        ret = TRUE;
    } else if (dump_type == to_file) {
        char* cmd = NULL;
        ;

        if (dumptrace >= 1)
            fprintf(stderr, "%s: closing %s\n",
                ProgramName, dumpname);
        if (rename(dumpnamepart, dumpname)) {
            logerr("rename: %s", strerror(errno));
            return ret;
        }
        if (kick_cmd != NULL)
            if (asprintf(&cmd, "%s %s &", kick_cmd, dumpname) < 0) {
                logerr("asprintf: %s", strerror(errno));
                cmd = NULL;
            }
        free(dumpnamepart);
        dumpnamepart = NULL;
        free(dumpname);
        dumpname = NULL;
        if (cmd != NULL) {
            int x = system(cmd);
            if (x)
                logerr("system: \"%s\" returned %d", cmd, x);
            free(cmd);
        }
        if (kick_cmd == NULL && options.dump_format != cbor && options.dump_format != cds)
            ret = TRUE;
    }
    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        int x;
        if (!p->close)
            continue;
        x = (*p->close)(ts);
        if (x)
            logerr("%s_close returned %d", p->name, x);
    }
    dump_state = dumper_closed;
    return (ret);
}

#if HAVE_FOPENCOOKIE
static ssize_t gzip_cookie_write(void* cookie, const char* buf, size_t size)
#elif HAVE_FUNOPEN
static int gzip_cookie_write(void* cookie, const char* buf, int size)
#endif
{
    return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned)size);
}

static int gzip_cookie_close(void* cookie)
{
    return gzclose((gzFile)cookie);
}

void dnscap_dump_open_gz(const char* path, FILE** fp)
{
    *fp = 0;

    gzFile z = gzopen(path, "w");
    if (z == NULL) {
        perror("gzopen");
        return;
    }

#if HAVE_FOPENCOOKIE
    static cookie_io_functions_t cookiefuncs = {
        NULL, gzip_cookie_write, NULL, gzip_cookie_close
    };

    *fp = fopencookie(z, "w", cookiefuncs);
    if (*fp == NULL) {
        perror("fopencookie");
        return;
    }
#elif HAVE_FUNOPEN
    *fp = funopen(z, NULL, gzip_cookie_write, NULL, gzip_cookie_close);
    if (*fp == NULL) {
        perror("funopen");
        return;
    }
#endif
}

pcap_dumper_t* dnscap_pcap_dump_open(pcap_t* pcap, const char* path)
{
    if (wantgzip) {
        FILE* fp = 0;
        dnscap_dump_open_gz(path, &fp);
        if (!fp) {
            return NULL;
        }
        return pcap_dump_fopen(pcap, fp);
    }

    return pcap_dump_open(pcap, path);
}
