/*
 * Copyright (c) 2025 OARC, Inc.
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

#include <errno.h>
#include <stdbool.h>
#include <zlib.h>
#include <lz4frame.h>
#include <zstd.h>
#include <lzma.h>
#include <bzlib.h>

#define ZSTRM_DEFAULT_IN_SIZE (256 * 1024)
#define ZSTRM_DEFAULT_OUT_SIZE (1024 * 1024)

#define debugprint(x...) // printf(x)

struct zstrm_ctx;
struct zstrm_ctx {
    void* _ctx;
    size_t (*_decompress)(struct zstrm_ctx*, size_t*);
    void (*_close)(struct zstrm_ctx*);

    void * in, *out;
    size_t in_size, out_size;
    size_t in_have, out_have;
    size_t in_at, out_at;

    FILE* fp;

    size_t total_read, total_compress_read;

    bool ended;
};

static struct zstrm_ctx* zstrm_create(size_t in_size, size_t out_size)
{
    struct zstrm_ctx* ctx = calloc(1, sizeof(struct zstrm_ctx));
    assert(ctx);

    ctx->in_size = in_size;
    assert((ctx->in = malloc(ctx->in_size)));
    ctx->out_size = out_size;
    assert((ctx->out = malloc(ctx->out_size)));

    return ctx;
}

#define ctx ((struct zstrm_ctx*)ctx_)
#if HAVE_FOPENCOOKIE
static ssize_t zstrm_read(void* ctx_, char* dst, size_t len)
#elif HAVE_FUNOPEN
static int zstrm_read(void* ctx_, char* dst, int len)
#endif
{
    size_t need = len;

    for (;;) {
        // check if we have enough in the out buffer, if so return what was requested
        if (ctx->out_have >= need) {
            memcpy(dst, ctx->out + ctx->out_at, need);
            ctx->out_have -= need;
            ctx->out_at += need;
            ctx->total_read += need;
            debugprint("have %zu\n", need);
            return len;
        }

        // empty out the out buffer
        debugprint("buf drain, want %zu, had %zu\n", need, ctx->out_have);
        memcpy(dst, ctx->out + ctx->out_at, ctx->out_have);
        need -= ctx->out_have;
        dst += ctx->out_have;
        ctx->total_read += ctx->out_have;
        ctx->out_have = 0;
        ctx->out_at   = 0;

        size_t in_used, out_new;
        for (;;) {
            // try and fill the in buffer
            if (ctx->in_have < ctx->in_size) {
                ssize_t n = fread(ctx->in + ctx->in_at, 1, ctx->in_size - ctx->in_have, ctx->fp);
                debugprint("fread %zd\n", n);
                if (n < 0) {
                    return n;
                }
                ctx->in_at += n;
                ctx->in_have += n;
                ctx->total_compress_read += n;
            }

            // decompress buffers
            in_used = 0;
            debugprint("pre decompress, in %zu\n", ctx->in_have);
            out_new = ctx->_decompress(ctx, &in_used);

            // if in buffer got drained but nothing in out buffer, then it needs more input
            if (ctx->in_have && in_used == ctx->in_have && !out_new && !ctx->ended) {
                debugprint("in drained, need more\n");
                ctx->in_at   = 0;
                ctx->in_have = 0;
                continue;
            }
            break;
        }

        if (ctx->in_have) {
            // move what we have left in the in buffer to the start of the buffer
            if (in_used < ctx->in_have) {
                ctx->in_have -= in_used;
                memmove(ctx->in, ctx->in + in_used, ctx->in_have);
                ctx->in_at = ctx->in_have;
            } else {
                ctx->in_at   = 0;
                ctx->in_have = 0;
            }
        }
        debugprint("post decompress, in %zu, out %zu\n", ctx->in_have, out_new);
        if (!out_new) {
            // nothing new returned
            debugprint("not enough, %zu\n", len - need);
            return len - need;
        }

        ctx->out_at   = 0;
        ctx->out_have = out_new;
    }
}
#if HAVE_FOPENCOOKIE
static int zstrm_seek(void* ctx_, off_t* offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        if (offset) {
            last_total_compress_read = ctx->total_compress_read;
            *offset                  = ctx->total_read;
            return 0;
        }
    default:
        break;
    }
    return -1;
}
#elif HAVE_FUNOPEN
static off_t zstrm_seek(void* ctx_, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_CUR:
        last_total_compress_read = ctx->total_compress_read;
        return ctx->total_read;
    default:
        break;
    }
    errno = EINVAL;
    return -1;
}
#endif
static int zstrm_close(void* ctx_)
{
    FILE* fp = ctx->fp;

    ctx->_close(ctx);
    free(ctx->in);
    free(ctx->out);
    free(ctx);

    return fclose(fp);
}
#undef ctx

/* GZ compression */

#define gz ((z_stream*)(ctx->_ctx))
static size_t zstrm_decompress_gz(struct zstrm_ctx* ctx, size_t* in_used)
{
    if (ctx->ended) {
        return 0;
    }

    int action = Z_NO_FLUSH;

    if (!ctx->in_have) {
        action = Z_FINISH;
    }

    gz->next_in   = ctx->in;
    gz->avail_in  = ctx->in_have;
    gz->next_out  = ctx->out;
    gz->avail_out = ctx->out_size;

    int ret = inflate(gz, action);
    if (ret != Z_OK && ret != Z_STREAM_END) {
        if (ret == Z_BUF_ERROR) {
            // not fatal, no progress made
            return 0;
        }
        fprintf(stderr, "inflate() failed: %d\n", ret);
        exit(1);
    }
    if (ret == Z_STREAM_END) {
        ctx->ended = true;
    }

    *in_used = ctx->in_have - gz->avail_in;
    return ctx->out_size - gz->avail_out;
}

static void zstrm_close_gz(struct zstrm_ctx* ctx)
{
    inflateEnd(gz);
}

/* LZ4 compression */

#define lz4 ((LZ4F_dctx*)(ctx->_ctx))
static size_t zstrm_decompress_lz4(struct zstrm_ctx* ctx, size_t* in_used)
{
    LZ4F_decompressOptions_t opts = {
        .stableDst = 1,
    };

    size_t dst_size = ctx->out_size,
           src_size = ctx->in_have;

    LZ4F_errorCode_t code = LZ4F_decompress(lz4, ctx->out, &dst_size, ctx->in, &src_size, &opts);
    if (LZ4F_isError(code)) {
        fprintf(stderr, "LZ4F_decompress() failed: %s\n", LZ4F_getErrorName(code));
        exit(1);
    }

    *in_used = src_size;
    return dst_size;
}

static void zstrm_close_lz4(struct zstrm_ctx* ctx)
{
    LZ4F_errorCode_t code;
    if ((code = LZ4F_freeDecompressionContext(lz4))) {
        fprintf(stderr, "LZ4F_freeDecompressionContext() failed: %s\n", LZ4F_getErrorName(code));
        exit(1);
    }
}

/* ZSTD compression */

#define zstd ((ZSTD_DCtx*)(ctx->_ctx))
static size_t zstrm_decompress_zstd(struct zstrm_ctx* ctx, size_t* in_used)
{
    ZSTD_inBuffer zin = {
        .src  = ctx->in,
        .size = ctx->in_have,
        .pos  = 0,
    };
    ZSTD_outBuffer zout = {
        .dst  = ctx->out,
        .size = ctx->out_size,
        .pos  = 0,
    };

    size_t code = ZSTD_decompressStream(zstd, &zout, &zin);
    if (ZSTD_isError(code)) {
        fprintf(stderr, "ZSTD_decompressStream() failed: %s\n", ZSTD_getErrorName(code));
        exit(1);
    }

    *in_used = zin.pos;
    return zout.pos;
}

static void zstrm_close_zstd(struct zstrm_ctx* ctx)
{
    ZSTD_freeDCtx(zstd);
}

/* LZMA compression */

#define lzma ((lzma_stream*)(ctx->_ctx))
static size_t zstrm_decompress_lzma(struct zstrm_ctx* ctx, size_t* in_used)
{
    if (ctx->ended) {
        return 0;
    }

    lzma_action action = LZMA_RUN;

    if (!ctx->in_have) {
        action = LZMA_FINISH;
    }

    lzma->next_in   = ctx->in;
    lzma->avail_in  = ctx->in_have;
    lzma->next_out  = ctx->out;
    lzma->avail_out = ctx->out_size;

    lzma_ret ret = lzma_code(lzma, action);
    if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
        if (ret == LZMA_BUF_ERROR) {
            // not fatal, no progress made
            return 0;
        }
        fprintf(stderr, "lzma_code() failed: %d\n", ret);
        exit(1);
    }
    if (ret == LZMA_STREAM_END) {
        ctx->ended = true;
    }

    *in_used = ctx->in_have - lzma->avail_in;
    return ctx->out_size - lzma->avail_out;
}

static void zstrm_close_lzma(struct zstrm_ctx* ctx)
{
    lzma_end(lzma);
}

/* BZ2 compression */

#define bz2 ((bz_stream*)(ctx->_ctx))
static size_t zstrm_decompress_bz2(struct zstrm_ctx* ctx, size_t* in_used)
{
    if (ctx->ended) {
        return 0;
    }

    bz2->next_in   = ctx->in;
    bz2->avail_in  = ctx->in_have;
    bz2->next_out  = ctx->out;
    bz2->avail_out = ctx->out_size;

    int ret = BZ2_bzDecompress(bz2);
    if (ret != BZ_OK && ret != BZ_STREAM_END) {
        fprintf(stderr, "BZ2_bzDecompress() failed: %d\n", ret);
        exit(1);
    }
    if (ret == BZ_STREAM_END) {
        ctx->ended = true;
    }

    *in_used = ctx->in_have - bz2->avail_in;
    return ctx->out_size - bz2->avail_out;
}

static void zstrm_close_bz2(struct zstrm_ctx* ctx)
{
    BZ2_bzDecompressEnd(bz2);
}

/* ZSTRM functions */

FILE* zstrm_open(struct zstrm_ctx* ctx, const char* file)
{
    FILE* fp;

    if (!(ctx->fp = fopen(file, "r"))) {
        perror("fopen");
        exit(1);
    }

#if HAVE_FOPENCOOKIE
    static cookie_io_functions_t cookiefuncs = {
        zstrm_read, 0, zstrm_seek, zstrm_close
    };
    fp = fopencookie(ctx, "r", cookiefuncs);
    if (fp == NULL) {
        perror("fopencookie");
        exit(1);
    }
#elif HAVE_FUNOPEN
    fp = funopen(ctx, zstrm_read, 0, zstrm_seek, zstrm_close);
    if (fp == NULL) {
        perror("funopen");
        exit(1);
    }
#endif

    return fp;
}

FILE* zstrm_open_gz(const char* file)
{
    z_stream* gz_ctx = calloc(1, sizeof(z_stream));
    assert(gz_ctx);
    int ret = inflateInit2(gz_ctx, 32);
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit2() failed: %d\n", ret);
        exit(1);
    }

    struct zstrm_ctx* ctx = zstrm_create(ZSTRM_DEFAULT_IN_SIZE, ZSTRM_DEFAULT_OUT_SIZE);
    ctx->_ctx             = gz_ctx;
    ctx->_decompress      = zstrm_decompress_gz;
    ctx->_close           = zstrm_close_gz;

    return zstrm_open(ctx, file);
}

FILE* zstrm_open_lz4(const char* file)
{
    LZ4F_errorCode_t code;
    LZ4F_dctx*       lz4_ctx;
    if ((code = LZ4F_createDecompressionContext(&lz4_ctx, LZ4F_VERSION))) {
        fprintf(stderr, "LZ4F_createDecompressionContext() failed: %s\n", LZ4F_getErrorName(code));
        exit(1);
    }

    struct zstrm_ctx* ctx = zstrm_create(ZSTRM_DEFAULT_IN_SIZE, ZSTRM_DEFAULT_OUT_SIZE);
    ctx->_ctx             = lz4_ctx;
    ctx->_decompress      = zstrm_decompress_lz4;
    ctx->_close           = zstrm_close_lz4;

    return zstrm_open(ctx, file);
}

FILE* zstrm_open_zstd(const char* file)
{
    ZSTD_DCtx* zstd_ctx = ZSTD_createDCtx();
    assert(zstd_ctx);

    struct zstrm_ctx* ctx = zstrm_create(ZSTD_DStreamInSize(), ZSTD_DStreamOutSize());
    ctx->_ctx             = zstd_ctx;
    ctx->_decompress      = zstrm_decompress_zstd;
    ctx->_close           = zstrm_close_zstd;

    return zstrm_open(ctx, file);
}

static lzma_stream lzma_stream_init = LZMA_STREAM_INIT;

FILE* zstrm_open_xz(const char* file)
{
    lzma_stream* lzma_ctx = calloc(1, sizeof(lzma_stream));
    assert(lzma_ctx);
    *lzma_ctx    = lzma_stream_init;
    lzma_ret ret = lzma_stream_decoder(lzma_ctx, UINT64_MAX, LZMA_CONCATENATED);
    if (ret != LZMA_OK) {
        fprintf(stderr, "lzma_stream_decoder() error: %d\n", ret);
        exit(1);
    }

    struct zstrm_ctx* ctx = zstrm_create(ZSTRM_DEFAULT_IN_SIZE, ZSTRM_DEFAULT_OUT_SIZE);
    ctx->_ctx             = lzma_ctx;
    ctx->_decompress      = zstrm_decompress_lzma;
    ctx->_close           = zstrm_close_lzma;

    return zstrm_open(ctx, file);
}

FILE* zstrm_open_bz2(const char* file)
{
    bz_stream* bz2_ctx = calloc(1, sizeof(bz_stream));
    assert(bz2_ctx);
    int ret = BZ2_bzDecompressInit(bz2_ctx, 0, 0);
    if (ret != BZ_OK) {
        fprintf(stderr, "BZ2_bzDecompressInit() error: %d\n", ret);
        exit(1);
    }

    struct zstrm_ctx* ctx = zstrm_create(ZSTRM_DEFAULT_IN_SIZE, ZSTRM_DEFAULT_OUT_SIZE);
    ctx->_ctx             = bz2_ctx;
    ctx->_decompress      = zstrm_decompress_bz2;
    ctx->_close           = zstrm_close_bz2;

    return zstrm_open(ctx, file);
}
