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

#include "pcaps.h"
#include "log.h"
#include "network.h"

#include "pcap-thread/pcap_thread_ext_frag.h"

#include <zlib.h>
#include <lz4frame.h>
#include <zstd.h>
#include <lzma.h>
#include <errno.h>

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

static pcap_thread_ext_frag_conf_t frag_conf_v4 = PCAP_THREAD_EXT_FRAG_CONF_T_INIT;
static pcap_thread_ext_frag_conf_t frag_conf_v6 = PCAP_THREAD_EXT_FRAG_CONF_T_INIT;

/* GZ compression */

#if HAVE_FOPENCOOKIE
static ssize_t gzip_cookie_read(void* cookie, char* buf, size_t size)
#elif HAVE_FUNOPEN
static int gzip_cookie_read(void* cookie, char* buf, int size)
#endif
{
    return gzread((gzFile)cookie, buf, size);
}
#if HAVE_FOPENCOOKIE
static int gzip_cookie_seek(void* cookie, off_t* offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        if (offset) {
            int ret = gztell((gzFile)cookie);
            *offset = ret;
            return 0;
        }
    default:
        break;
    }
    return -1;
}
#elif HAVE_FUNOPEN
static off_t gzip_cookie_seek(void* cookie, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        return gztell((gzFile)cookie);
    default:
        break;
    }
    errno = EINVAL;
    return -1;
}
#endif
static int gzip_cookie_close(void* cookie)
{
    return gzclose((gzFile)cookie);
}

/* LZ4 compression */

struct _lz4_ctx {
    LZ4F_dctx*               ctx;
    LZ4F_decompressOptions_t opts;

    void * in, *out;
    size_t in_size, out_size;
    size_t in_have, out_have;
    size_t in_at, out_at;

    void* file;

    size_t total_read;
};
#define lz4 ((struct _lz4_ctx*)cookie)
#if HAVE_FOPENCOOKIE
static ssize_t lz4_cookie_read(void* cookie, char* dst, size_t len)
#elif HAVE_FUNOPEN
static int lz4_cookie_read(void* cookie, char* dst, int len)
#endif
{
    size_t need = len;

    for (;;) {
        if (lz4->out_have >= need) {
            memcpy(dst, lz4->out + lz4->out_at, need);
            lz4->out_have -= need;
            lz4->out_at += need;
            lz4->total_read += need;
            return len;
        }

        memcpy(dst, lz4->out + lz4->out_at, lz4->out_have);
        need -= lz4->out_have;
        dst += lz4->out_have;
        lz4->total_read += lz4->out_have;

        ssize_t n = fread(lz4->in + lz4->in_at, 1, lz4->in_size - lz4->in_have, lz4->file);
        if (n < 0) {
            return n;
        }
        lz4->in_at += n;
        lz4->in_have += n;
        if (!lz4->in_have) {
            if (need < len) {
                return len - need;
            }
            return 0;
        }

        size_t dst_size = lz4->out_size, src_size = lz4->in_have;
        size_t code = LZ4F_decompress(lz4->ctx, lz4->out, &dst_size, lz4->in, &src_size, &lz4->opts);
        if (LZ4F_isError(code)) {
            fprintf(stderr, "LZ4F_decompress() failed: %s\n", LZ4F_getErrorName(code));
            exit(1);
        }

        if (src_size < lz4->in_have) {
            lz4->in_have -= src_size;
            memmove(lz4->in, lz4->in + src_size, lz4->in_have);
            lz4->in_at = lz4->in_have;
        } else {
            lz4->in_at   = 0;
            lz4->in_have = 0;
        }

        lz4->out_at   = 0;
        lz4->out_have = dst_size;
    }
}
#if HAVE_FOPENCOOKIE
static int lz4_cookie_seek(void* cookie, off_t* offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        if (offset) {
            *offset = lz4->total_read;
            return 0;
        }
    default:
        break;
    }
    return -1;
}
#elif HAVE_FUNOPEN
static off_t lz4_cookie_seek(void* cookie, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        return lz4->total_read;
    default:
        break;
    }
    errno = EINVAL;
    return -1;
}
#endif
static int lz4_cookie_close(void* cookie)
{
    FILE* fp = lz4->file;

    LZ4F_errorCode_t code;
    if ((code = LZ4F_freeDecompressionContext(lz4->ctx))) {
        fprintf(stderr, "LZ4F_freeDecompressionContext() failed: %s\n", LZ4F_getErrorName(code));
        exit(1);
    }
    free(lz4->in);
    free(lz4->out);
    free(lz4);

    return fclose(fp);
}

/* ZSTD compression */

struct _zstd_ctx {
    ZSTD_DCtx*     ctx;
    ZSTD_inBuffer  zin;
    ZSTD_outBuffer zout;

    void * in, *out;
    size_t in_size, out_size;
    size_t in_have, out_have;
    size_t in_at, out_at;

    void* file;

    size_t total_read;
};
#define zstd ((struct _zstd_ctx*)cookie)

#if HAVE_FOPENCOOKIE
static ssize_t zstd_cookie_read(void* cookie, char* dst, size_t len)
#elif HAVE_FUNOPEN
static int zstd_cookie_read(void* cookie, char* dst, int len)
#endif
{
    size_t need = len;

    for (;;) {
        if (zstd->out_have >= need) {
            memcpy(dst, zstd->out + zstd->out_at, need);
            zstd->out_have -= need;
            zstd->out_at += need;
            zstd->total_read += need;
            return len;
        }

        memcpy(dst, zstd->out + zstd->out_at, zstd->out_have);
        need -= zstd->out_have;
        dst += zstd->out_have;
        zstd->total_read += zstd->out_have;

        if (zstd->zin.pos >= zstd->zin.size) {
            ssize_t n = fread(zstd->in, 1, zstd->in_size, zstd->file);
            if (n < 1) {
                if (!n && need < len) {
                    return len - need;
                }
                return n;
            }
            zstd->zin.size = n;
            zstd->zin.pos  = 0;
        }

        zstd->zout.size = zstd->out_size;
        zstd->zout.pos  = 0;
        size_t code     = ZSTD_decompressStream(zstd->ctx, &zstd->zout, &zstd->zin);
        if (ZSTD_isError(code)) {
            fprintf(stderr, "ZSTD_decompressStream() failed: %s\n", ZSTD_getErrorName(code));
            exit(1);
        }

        zstd->out_have = zstd->zout.pos;
        zstd->out_at   = 0;
    }
}
#if HAVE_FOPENCOOKIE
static int zstd_cookie_seek(void* cookie, off_t* offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        if (offset) {
            *offset = zstd->total_read;
            return 0;
        }
    default:
        break;
    }
    return -1;
}
#elif HAVE_FUNOPEN
static off_t zstd_cookie_seek(void* cookie, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        return zstd->total_read;
    default:
        break;
    }
    errno = EINVAL;
    return -1;
}
#endif
static int zstd_cookie_close(void* cookie)
{
    FILE* fp = zstd->file;
    ZSTD_freeDCtx(zstd->ctx);
    free(zstd->in);
    free(zstd->out);
    free(zstd);
    return fclose(fp);
}

/* LZMA compression */

struct _lzma_ctx {
    lzma_stream strm;

    void * in, *out;
    size_t in_size, out_size;
    size_t in_have, out_have;
    size_t in_at, out_at;

    void* file;

    size_t total_read;
};
#define lzma ((struct _lzma_ctx*)cookie)
static lzma_stream lzma_stream_init = LZMA_STREAM_INIT;
#if HAVE_FOPENCOOKIE
static ssize_t lzma_cookie_read(void* cookie, char* dst, size_t len)
#elif HAVE_FUNOPEN
static int lzma_cookie_read(void* cookie, char* dst, int len)
#endif
{
    size_t need = len;

    lzma_action action = LZMA_RUN;
    uint8_t     inbuf[BUFSIZ];
    for (;;) {
        if (lzma->out_have >= need) {
            memcpy(dst, lzma->out + lzma->out_at, need);
            lzma->out_have -= need;
            lzma->out_at += need;
            lzma->total_read += need;
            return len;
        }

        memcpy(dst, lzma->out + lzma->out_at, lzma->out_have);
        need -= lzma->out_have;
        dst += lzma->out_have;
        lzma->total_read += lzma->out_have;

        ssize_t n = fread(inbuf, 1, sizeof(inbuf), lzma->file);
        if (n < 0) {
            return n;
        }
        if (!n) {
            action = LZMA_FINISH;
        }

        lzma->strm.next_in   = inbuf;
        lzma->strm.avail_in  = n;
        lzma->strm.next_out  = lzma->out;
        lzma->strm.avail_out = lzma->out_size;

        lzma_ret ret = lzma_code(&lzma->strm, action);
        if (ret != LZMA_OK) {
            if (ret == LZMA_STREAM_END) {
                if (need < len) {
                    return len - need;
                }
                return 0;
            }
            fprintf(stderr, "lzma_code() failed: %d\n", ret);
            exit(1);
        }

        lzma->out_at   = 0;
        lzma->out_have = lzma->out_size - lzma->strm.avail_out;
    }
}
#if HAVE_FOPENCOOKIE
static int lzma_cookie_seek(void* cookie, off_t* offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        if (offset) {
            *offset = lzma->total_read;
            return 0;
        }
    default:
        break;
    }
    return -1;
}
#elif HAVE_FUNOPEN
static off_t lzma_cookie_seek(void* cookie, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        return lzma->total_read;
    default:
        break;
    }
    errno = EINVAL;
    return -1;
}
#endif
static int lzma_cookie_close(void* cookie)
{
    FILE* fp = lzma->file;

    lzma_end(&lzma->strm);
    free(lzma->out);
    free(lzma);

    return fclose(fp);
}

/* compression end */

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
            if (options.max_ipv4_fragments > 0 && (err = pcap_thread_ext_frag_conf_set_fragments(&frag_conf_v4, options.max_ipv4_fragments)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_fragments()", err);
                exit(1);
            }
            if (options.max_ipv4_fragments_per_packet > 0 && (err = pcap_thread_ext_frag_conf_set_per_packet(&frag_conf_v4, options.max_ipv4_fragments_per_packet)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_per_packet()", err);
                exit(1);
            }
            if ((err = pcap_thread_set_callback_ipv4_frag(&pcap_thread, pcap_thread_ext_frag_layer_callback(&frag_conf_v4))) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_set_callback_ipv4_frag()", err);
                exit(1);
            }
        }
        if (options.defrag_ipv6) {
            if (options.max_ipv6_fragments > 0 && (err = pcap_thread_ext_frag_conf_set_fragments(&frag_conf_v6, options.max_ipv6_fragments)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_fragments()", err);
                exit(1);
            }
            if (options.max_ipv6_fragments_per_packet > 0 && (err = pcap_thread_ext_frag_conf_set_per_packet(&frag_conf_v6, options.max_ipv6_fragments_per_packet)) != PCAP_THREAD_OK) {
                print_pcap_thread_error("pcap_thread_ext_frag_conf_set_per_packet()", err);
                exit(1);
            }
            if ((err = pcap_thread_set_callback_ipv6_frag(&pcap_thread, pcap_thread_ext_frag_layer_callback(&frag_conf_v6))) != PCAP_THREAD_OK) {
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
        if (pcap_offline) {
            FILE* fp = 0;

            char* dot = strrchr(mypcap->name, '.');
            if (dot) {
                if (!strcasecmp(dot, ".gz")) {
                    gzFile cookie = gzopen(mypcap->name, "r");
                    if (cookie == NULL) {
                        perror("gzopen");
                        exit(1);
                    }

#if HAVE_FOPENCOOKIE
                    static cookie_io_functions_t cookiefuncs = {
                        gzip_cookie_read, 0, gzip_cookie_seek, gzip_cookie_close
                    };
                    fp = fopencookie(cookie, "r", cookiefuncs);
                    if (fp == NULL) {
                        perror("fopencookie");
                        exit(1);
                    }
#elif HAVE_FUNOPEN
                    fp = funopen(cookie, gzip_cookie_read, 0, gzip_cookie_seek, gzip_cookie_close);
                    if (fp == NULL) {
                        perror("funopen");
                        return;
                    }
#endif
                } else if (!strcasecmp(dot, ".lz4")) {
                    LZ4F_errorCode_t code;
                    struct _lz4_ctx* cookie = calloc(1, sizeof(struct _lz4_ctx));
                    assert(cookie);
                    lz4->in_size = 256 * 1024;
                    assert((lz4->in = malloc(lz4->in_size)));
                    lz4->out_size = 256 * 1024;
                    assert((lz4->out = malloc(lz4->out_size)));
                    if ((code = LZ4F_createDecompressionContext(&lz4->ctx, LZ4F_VERSION))) {
                        fprintf(stderr, "LZ4F_createDecompressionContext() failed: %s\n", LZ4F_getErrorName(code));
                        exit(1);
                    }
                    lz4->opts.stableDst = 1;

                    if (!(lz4->file = fopen(mypcap->name, "r"))) {
                        perror("fopen");
                        exit(1);
                    }

#if HAVE_FOPENCOOKIE
                    static cookie_io_functions_t cookiefuncs = {
                        lz4_cookie_read, 0, lz4_cookie_seek, lz4_cookie_close
                    };
                    fp = fopencookie(cookie, "r", cookiefuncs);
                    if (fp == NULL) {
                        perror("fopencookie");
                        exit(1);
                    }
#elif HAVE_FUNOPEN
                    fp = funopen(cookie, lz4_cookie_read, 0, lz4_cookie_seek, lz4_cookie_close);
                    if (fp == NULL) {
                        perror("funopen");
                        return;
                    }
#endif
                } else if (!strcasecmp(dot, ".zst")) {
                    struct _zstd_ctx* cookie = calloc(1, sizeof(struct _zstd_ctx));
                    assert(cookie);
                    assert((zstd->ctx = ZSTD_createDCtx()));
                    zstd->in_size = ZSTD_DStreamInSize();
                    assert((zstd->in = malloc(zstd->in_size)));
                    zstd->out_size = ZSTD_DStreamOutSize();
                    assert((zstd->out = malloc(zstd->out_size)));

                    zstd->zin.src   = zstd->in;
                    zstd->zout.dst  = zstd->out;
                    zstd->zout.size = zstd->out_size;

                    if (!(zstd->file = fopen(mypcap->name, "r"))) {
                        perror("fopen");
                        exit(1);
                    }

#if HAVE_FOPENCOOKIE
                    static cookie_io_functions_t cookiefuncs = {
                        zstd_cookie_read, 0, zstd_cookie_seek, zstd_cookie_close
                    };
                    fp = fopencookie(cookie, "r", cookiefuncs);
                    if (fp == NULL) {
                        perror("fopencookie");
                        exit(1);
                    }
#elif HAVE_FUNOPEN
                    fp = funopen(cookie, zstd_cookie_read, 0, zstd_cookie_seek, zstd_cookie_close);
                    if (fp == NULL) {
                        perror("funopen");
                        return;
                    }
#endif
                } else if (!strcasecmp(dot, ".xz")) {
                    struct _lzma_ctx* cookie = calloc(1, sizeof(struct _lzma_ctx));
                    assert(cookie);
                    lzma->strm   = lzma_stream_init;
                    lzma_ret ret = lzma_stream_decoder(&lzma->strm, UINT64_MAX, LZMA_CONCATENATED);
                    if (ret != LZMA_OK) {
                        fprintf(stderr, "lzma_stream_decoder() error: %d\n", ret);
                        exit(1);
                    }
                    lzma->out_size = 256 * 1024;
                    assert((lzma->out = malloc(lzma->out_size)));

                    if (!(lzma->file = fopen(mypcap->name, "r"))) {
                        perror("fopen");
                        exit(1);
                    }

#if HAVE_FOPENCOOKIE
                    static cookie_io_functions_t cookiefuncs = {
                        lzma_cookie_read, 0, lzma_cookie_seek, lzma_cookie_close
                    };
                    fp = fopencookie(cookie, "r", cookiefuncs);
                    if (fp == NULL) {
                        perror("fopencookie");
                        exit(1);
                    }
#elif HAVE_FUNOPEN
                    fp = funopen(cookie, lzma_cookie_read, 0, lzma_cookie_seek, lzma_cookie_close);
                    if (fp == NULL) {
                        perror("funopen");
                        return;
                    }
#endif
                }
            }
            if (fp)
                err = pcap_thread_open_offline_fp(&pcap_thread, mypcap->name, fp, (u_char*)mypcap);
            else
                err = pcap_thread_open_offline(&pcap_thread, mypcap->name, (u_char*)mypcap);
        } else
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
