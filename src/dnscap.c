/* dnscap - DNS capture utility
 *
 * By Paul Vixie (ISC) and Duane Wessels (Measurement Factory), 2007.
 */

/*
 * Copyright (c) 2016-2017, OARC, Inc.
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

#include "dnscap.h"
#include "args.h"
#include "bpft.h"
#include "pcaps.h"
#include "dumper.h"
#include "daemon.h"
#include "log.h"
#include "sig.h"

plugin_list     plugins;
const char*     ProgramName = "amnesia";
int             dumptrace   = 0;
int             flush       = FALSE;
vlan_list       vlans_excl;
vlan_list       vlans_incl;
unsigned        msg_wanted = MSG_QUERY;
unsigned        dir_wanted = DIR_INITIATE | DIR_RESPONSE;
unsigned        end_hide   = 0U;
unsigned        err_wanted = ERR_NO | ERR_YES; /* accept all by default */
tcpstate_list   tcpstates;
int             tcpstate_count = 0;
endpoint_list   initiators, not_initiators;
endpoint_list   responders, not_responders;
endpoint_list   drop_responders; /* drops only responses from these hosts */
myregex_list    myregexes;
mypcap_list     mypcaps;
mypcap_ptr      pcap_offline       = NULL;
const char*     dump_base          = NULL;
char*           dump_suffix        = 0;
char*           extra_bpf          = NULL;
enum dump_type  dump_type          = nowhere;
enum dump_state dump_state         = dumper_closed;
const char*     kick_cmd           = NULL;
unsigned        limit_seconds      = 0U;
time_t          next_interval      = 0;
unsigned        limit_packets      = 0U;
size_t          limit_pcapfilesize = 0U;
pcap_t*         pcap_dead;
pcap_dumper_t*  dumper;
time_t          dumpstart;
unsigned        msgcount;
size_t          capturedbytes = 0;
char *          dumpname, *dumpnamepart;
char*           bpft;
unsigned        dns_port       = DNS_PORT;
int             promisc        = TRUE;
int             monitor_mode   = FALSE;
int             immediate_mode = FALSE;
int             background     = FALSE;
char            errbuf[PCAP_ERRBUF_SIZE];
int             v6bug     = FALSE;
int             wantgzip  = 0;
int             wantfrags = FALSE;
int             wanticmp  = FALSE;
int             wanttcp   = FALSE;
int             preso     = FALSE;
#ifdef USE_SECCOMP
int use_seccomp = FALSE;
#endif
int                main_exit            = FALSE;
int                alarm_set            = FALSE;
time_t             start_time           = 0;
time_t             stop_time            = 0;
int                print_pcap_stats     = FALSE;
uint64_t           pcap_drops           = 0;
my_bpftimeval      last_ts              = { 0, 0 };
unsigned long long mem_limit            = (unsigned)MEM_MAX; /* process memory limit */
int                mem_limit_set        = 1; /* TODO: Should be configurable */
const char         DROPTOUSER[]         = "nobody";
pcap_thread_t      pcap_thread          = PCAP_THREAD_T_INIT;
int                only_offline_pcaps   = TRUE;
int                dont_drop_privileges = FALSE;
options_t          options              = OPTIONS_T_DEFAULTS;

int main(int argc, char* argv[])
{
    struct plugin* p;
    struct timeval now;

    res_init();
    parse_args(argc, argv);
    gettimeofday(&now, 0);
    if (start_time) {
        if (now.tv_sec < start_time) {
            char       when[100];
            struct tm* tm = gmtime(&start_time);
            strftime(when, sizeof when, "%F %T", tm);
            fprintf(stderr, "Sleeping for %d seconds until %s UTC\n",
                (int)(start_time - now.tv_sec), when);
            sleep(start_time - now.tv_sec);
            fprintf(stderr, "Awake.\n");
        }
    }
    prepare_bpft();
    open_pcaps();
    if (dump_type == to_stdout)
        dumper_open(now);
    INIT_LIST(tcpstates);

    if (!dont_drop_privileges && !only_offline_pcaps) {
        drop_privileges();
    }

    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        if (p->start)
            if (0 != (*p->start)(logerr)) {
                logerr("%s_start returned non-zero", p->name);
                exit(1);
            }
    }
    if (dump_type == nowhere)
        dumpstart = time(NULL);
    if (background)
        daemonize();

#if HAVE_PTHREAD
    /*
     * Defer signal setup until we have dropped privileges and daemonized,
     * otherwise signals might not reach us because different threads
     * are running under different users/access
     */
    {
        sigset_t  set;
        int       err;
        pthread_t thread;

        sigfillset(&set);
        if ((err = pthread_sigmask(SIG_BLOCK, &set, 0))) {
            logerr("pthread_sigmask: %s", strerror(err));
            exit(1);
        }

        sigemptyset(&set);
        sigaddset(&set, SIGHUP);
        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGALRM);
        sigaddset(&set, SIGTERM);
        sigaddset(&set, SIGQUIT);

        if ((err = pthread_create(&thread, 0, &sigthread, (void*)&set))) {
            logerr("pthread_create: %s", strerror(err));
            exit(1);
        }
    }
#else
    {
        sigset_t set;

        sigfillset(&set);
        sigdelset(&set, SIGHUP);
        sigdelset(&set, SIGINT);
        sigdelset(&set, SIGALRM);
        sigdelset(&set, SIGTERM);
        sigdelset(&set, SIGQUIT);

        if (sigprocmask(SIG_BLOCK, &set, 0)) {
            logerr("sigprocmask: %s", strerror(errno));
            exit(1);
        }
    }

    setsig(SIGHUP, TRUE);
    setsig(SIGINT, TRUE);
    setsig(SIGALRM, FALSE);
    setsig(SIGTERM, TRUE);
    setsig(SIGQUIT, TRUE);
#endif

    while (!main_exit)
        poll_pcaps();
    /* close PCAPs after dumper_close() to have statistics still available during dumper_close() */
    if (dumper_opened == dump_state)
        (void)dumper_close(last_ts);
    close_pcaps();
    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
        if (p->stop)
            (*p->stop)();
    }
    options_free(&options);
    return 0;
}
