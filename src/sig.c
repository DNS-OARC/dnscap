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

#include "sig.h"
#include "log.h"
#include "dumper.h"
#include "pcaps.h"

void setsig(int sig, int oneshot)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    if (oneshot) {
        sa.sa_handler = sigbreak;
        sa.sa_flags   = SA_RESETHAND;
    } else {
        sa.sa_handler = sigclose;
        sa.sa_flags   = SA_RESTART;
    }
    if (sigaction(sig, &sa, NULL) < 0) {
        logerr("sigaction: %s", strerror(errno));
        exit(1);
    }
}

void sigclose(int signum)
{
    if (0 == last_ts.tv_sec)
        gettimeofday(&last_ts, NULL);
    if (signum == SIGALRM)
        alarm_set = FALSE;
    if (dumper_close(last_ts))
        breakloop_pcaps();
}

void sigbreak(int signum __attribute__((unused)))
{
    logerr("%s: signalled break", ProgramName);
    main_exit = TRUE;
    breakloop_pcaps();
}

void* sigthread(void* arg)
{
#if HAVE_PTHREAD
    sigset_t* set = (sigset_t*)arg;
    int       sig, err;

    while (1) {
        if ((err = sigwait(set, &sig))) {
            logerr("sigwait: %s", strerror(err));
            return 0;
        }

        switch (sig) {
        case SIGALRM:
            sigclose(sig);
            break;

        default:
            sigbreak(sig);
            break;
        }
    }
#endif

    return 0;
}
