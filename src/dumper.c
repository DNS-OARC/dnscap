/*
 * Copyright (c) 2016-2022, OARC, Inc.
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

/*
 * when flags & DNSCAP_OUTPUT_ISDNS, payload points to a DNS packet
 */
void output(const char* descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char* pkt_copy, const unsigned olen,
    const u_char* payload, const unsigned payloadlen)
{
    struct plugin* p;

    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        if (p->filter && (*p->filter)(descr, &from, &to, proto, flags, sport, dport, ts, pkt_copy, olen, payload, payloadlen)) {
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
            struct pcap_pkthdr h;

            memset(&h, 0, sizeof h);
            h.ts  = ts;
            h.len = h.caplen = olen;
            pcap_dump((u_char*)dumper, &h, pkt_copy);
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
            int ret = output_cds(from, to, proto, flags, sport, dport, ts, pkt_copy, olen, payload, payloadlen);

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
        }
    }
    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link))
        if (p->output)
            (*p->output)(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, olen, payload, payloadlen);
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
        if (asprintf(&dumpname, "%s.%s.%06lu%s",
                dump_base, sbuf,
                (u_long)ts.tv_usec, dump_suffix ? dump_suffix : "")
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

#if HAVE_ZLIB_H
#if HAVE_FUNOPEN
static int
gzip_cookie_write(void* cookie, const char* buf, int size)
{
    return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned)size);
}
#elif HAVE_FOPENCOOKIE
static ssize_t
gzip_cookie_write(void* cookie, const char* buf, size_t size)
{
    return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned)size);
}
#endif

static int
gzip_cookie_close(void* cookie)
{
    return gzclose((gzFile)cookie);
}
#endif /* HAVE_ZLIB_H */

pcap_dumper_t* dnscap_pcap_dump_open(pcap_t* pcap, const char* path)
{
#if HAVE_ZLIB_H
#if HAVE_GZOPEN
    if (wantgzip) {
        FILE*  fp = NULL;
        gzFile z  = gzopen(path, "w");
        if (z == NULL) {
            perror("gzopen");
            return NULL;
        }

#if HAVE_FUNOPEN
        fp = funopen(z, NULL, gzip_cookie_write, NULL, gzip_cookie_close);
        if (fp == NULL) {
            perror("funopen");
            return NULL;
        }
#elif HAVE_FOPENCOOKIE
        {
            static cookie_io_functions_t cookiefuncs = {
                NULL, gzip_cookie_write, NULL, gzip_cookie_close
            };

            fp = fopencookie(z, "w", cookiefuncs);
            if (fp == NULL) {
                perror("fopencookie");
                return NULL;
            }
        }
#endif
        return pcap_dump_fopen(pcap, fp);
    }
#endif /* HAVE_GZOPEN */
#endif /* HAVE_ZLIB_H */

    return pcap_dump_open(pcap, path);
}
