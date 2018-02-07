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

#include "args.h"
#include "endpoint.h"
#include "iaddr.h"
#include "log.h"
#include "tcpstate.h"

/*
 * OpenBSD and Debian Stretch i386 need file local functions for export
 * to loaded modules, so use this for all platforms.
 */
void* _tcpstate_getcurr(void)
{
    return (void*)tcpstate_getcurr();
}

void _tcpstate_reset(void* tcpstate, const char* msg)
{
    tcpstate_reset((tcpstate_ptr)tcpstate, msg);
}

const char* _ia_str(iaddr ia)
{
    return ia_str(ia);
}

#ifdef __linux__
extern char* strptime(const char*, const char*, struct tm*);
#endif

time_t xtimegm(struct tm* tmp)
{
#if defined(__SVR4) && defined(__sun)
    char tz[3] = "TZ=";
    putenv((char*)tz);
    return mktime(tmp);
#else
    return timegm(tmp);
#endif
}

void usage(const char* msg)
{
    struct plugin* p;

    fprintf(stderr, "%s: usage error: %s\n", ProgramName, msg);
    fprintf(stderr, "\n");

    help_1();

    for (p = HEAD(plugins); p != NULL; p = NEXT(p, link))
        if (p->usage)
            (*p->usage)();

    fprintf(stderr,
        "\nnote: the -? or -\\? option will display full help text\n");

    exit(1);
}

void help_1(void)
{
    fprintf(stderr, "%s: version %s\n\n", ProgramName, PACKAGE_VERSION);
    fprintf(stderr,
        "usage: %s\n"
        "  [-?VbNpd1g6fTI"
#ifdef USE_SECCOMP
        "y"
#endif
        "SMD] [-o option=value]+\n"
        "  [-i <if>]+ [-r <file>]+ [-l <vlan>]+ [-L <vlan>]+\n"
        "  [-u <port>] [-m [qun]] [-e [nytfsxir]] [-h [ir]] [-s [ir]]\n"
        "  [-a <host>]+ [-z <host>]+ [-A <host>]+ [-Z <host>]+ [-Y <host>]+\n"
        "  [-w <base> [-W <suffix>] [-k <cmd>] -F <format>]\n"
        "  [-t <lim>] [-c <lim>] [-C <lim>]\n"
        "  [-x <pat>]+ [-X <pat>]+\n"
        "  [-B <datetime>] [-E <datetime>]\n"
        "  [-U <str>] [-P plugin.so <plugin options...>]\n",
        ProgramName);
}

void help_2(void)
{
    help_1();
    fprintf(stderr,
        "\noptions:\n"
        "  -? or -\\?  print these instructions and exit\n"
        "  -V         print version and exit\n"
        "  -o opt=val extended options, see man page for list of options\n"
        "  -b         run in background as daemon\n"
        "  -N         do not attempt to drop privileges, this is implicit\n"
        "             if only reading offline pcap files\n"
        "  -p         do not put interface in promiscuous mode\n"
        "  -d         dump verbose trace information to stderr, specify multiple\n"
        "             times to increase debugging\n"
        "  -1         flush output on every packet\n"
        "  -g         dump packets dig-style on stderr\n"
        "  -6         compensate for PCAP/BPF IPv6 bug\n"
        "  -f         include fragmented packets\n"
        "  -T         include TCP packets (DNS header filters will inspect only the\n"
        "             first DNS header, and the result will apply to all messages\n"
        "             in the TCP stream; DNS payload filters will not be applied.)\n"
        "  -I         include ICMP and ICMPv6 packets\n"
        "  -i <if>    select this live interface(s)\n"
        "  -r <file>  read this pcap file\n"
        "  -l <vlan>  select only these vlan(s) (4095 for all)\n"
        "  -L <vlan>  select these vlan(s) and non-VLAN frames (4095 for all)\n"
        "  -u <port>  dns port (default: 53)\n"
        "  -m [qun]   select messages: query, update, notify\n"
        "  -e [nytfsxir] select error/response code\n"
        "                 n = no error\n"
        "                 y = any error\n"
        "                 t = truncated response\n"
        "                 f = format error (rcode 1)\n"
        "                 s = server failure (rcode 2)\n"
        "                 x = nxdomain (rcode 3)\n"
        "                 i = not implemented (rcode 4)\n"
        "                 r = refused (rcode 5)\n"
        "  -h [ir]    hide initiators and/or responders\n"
        "  -s [ir]    select sides: initiations, responses\n"
        "  -a <host>  want messages from these initiator(s)\n"
        "  -z <host>  want messages from these responder(s)\n"
        "  -A <host>  want messages NOT to/from these initiator(s)\n"
        "  -Z <host>  want messages NOT to/from these responder(s)\n"
        "  -Y <host>  drop responses from these responder(s)\n"
        "  -w <base>  dump to <base>.<timesec>.<timeusec>\n"
        "  -W <suffix> add suffix to dump file name, e.g. '.pcap'\n"
        "  -k <cmd>   kick off <cmd> when each dump closes\n"
        "  -F <format> dump format: pcap (default), cbor, cds\n"
        "  -t <lim>   close dump or exit every/after <lim> secs\n"
        "  -c <lim>   close dump or exit every/after <lim> pkts\n"
        "  -C <lim>   close dump or exit every/after <lim> bytes captured\n"
        "  -x <pat>   select messages matching regex <pat>\n"
        "  -X <pat>   select messages not matching regex <pat>\n"
#ifdef USE_SECCOMP
        "  -y         enable seccomp-bpf\n"
#endif
        "  -S         show summarized statistics\n"
        "  -B <datetime> begin collecting at this date and time\n"
        "  -E <datetime> end collecting at this date and time\n"
        "  -M         set monitor mode on interfaces\n"
        "  -D         set immediate mode on interfaces\n"
        "  -U <str>   append 'and <str>' to the pcap filter\n"
        "  -P <plugin.so> load plugin, any argument after this is sent to the plugin!\n");
}

void check_gzip()
{
    char* dot = strrchr(dump_suffix, '.');
    if (dot) {
        wantgzip = (strcmp(dot, ".gz") == 0) ? TRUE : FALSE;
    }

#if !(HAVE_GZOPEN && (HAVE_FUNOPEN || HAVE_FOPENCOOKIE))
    if (wantgzip) {
        fprintf(stderr, "error: gzip compression requested but not supported\n");
        exit(1);
    }
#endif
}

int is_responder(iaddr ia)
{
    if (EMPTY(responders))
        return 1;
    if (ep_present(&responders, ia))
        return 1;
    return 0;
}

void parse_args(int argc, char* argv[])
{
    mypcap_ptr    mypcap;
    unsigned long ul;
    vlan_ptr      vlan;
    unsigned      u;
    int           ch;
    char*         p;

    if ((p = strrchr(argv[0], '/')) == NULL)
        ProgramName = argv[0];
    else
        ProgramName = p + 1;
    INIT_LIST(vlans_incl);
    INIT_LIST(vlans_excl);
    INIT_LIST(mypcaps);
    INIT_LIST(initiators);
    INIT_LIST(responders);
    INIT_LIST(not_initiators);
    INIT_LIST(not_responders);
    INIT_LIST(drop_responders);
    INIT_LIST(myregexes);
    INIT_LIST(plugins);
    while ((ch = getopt(argc, argv,
                "a:bc:de:fgh:i:k:l:m:o:pr:s:t:u:w:x:yz:"
                "A:B:C:DE:F:IL:MNP:STU:VW:X:Y:Z:16?"))
           != EOF) {
        switch (ch) {
        case 'o':
            if (option_parse(&options, optarg)) {
                fprintf(stderr, "%s: unknown or invalid extended option: %s\n", ProgramName, optarg);
                exit(1);
            }
            break;
        case 'b':
            background = TRUE;
            break;
        case 'N':
            dont_drop_privileges = TRUE;
            break;
        case 'p':
            promisc = FALSE;
            break;
        case 'd':
            dumptrace++;
            break;
        case '1':
            flush = TRUE;
            break;
        case 'g':
            preso = TRUE;
            break;
        case '6':
            v6bug = TRUE;
            break;
        case 'f':
            wantfrags = TRUE;
            break;
        case 'I':
            wanticmp = TRUE;
            break;
        case '?':
            help_2();
            exit(0);
            break;
        case 'V':
            printf("%s version %s\n", ProgramName, PACKAGE_VERSION);
            exit(0);
            break;
        case 'i':
            if (pcap_offline != NULL)
                usage("-i makes no sense after -r");
            mypcap = calloc(1, sizeof *mypcap);
            assert(mypcap != NULL);
            INIT_LINK(mypcap, link);
            mypcap->name = strdup(optarg);
            assert(mypcap->name != NULL);
            APPEND(mypcaps, mypcap, link);
            only_offline_pcaps = FALSE;
            break;
        case 'r':
            if (!EMPTY(mypcaps))
                usage("-r makes no sense after -i");
            pcap_offline = calloc(1, sizeof *pcap_offline);
            assert(pcap_offline != NULL);
            INIT_LINK(pcap_offline, link);
            pcap_offline->name = strdup(optarg);
            assert(pcap_offline->name != NULL);
            APPEND(mypcaps, pcap_offline, link);
            break;
        case 'l':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > MAX_VLAN)
                usage("vlan must be an integer 0..4095");
            vlan = calloc(1, sizeof *vlan);
            assert(vlan != NULL);
            INIT_LINK(vlan, link);
            vlan->vlan = (unsigned)ul;
            APPEND(vlans_excl, vlan, link);
            if (0 == ul)
                fprintf(stderr, "Warning: previous versions of %s "
                                "interpreted 0 as all VLANs. "
                                "If you want all VLANs now you must "
                                "specify %u.\n",
                    ProgramName, MAX_VLAN);
            break;
        case 'L':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul > MAX_VLAN)
                usage("vlan must be an integer 0..4095");
            vlan = calloc(1, sizeof *vlan);
            assert(vlan != NULL);
            INIT_LINK(vlan, link);
            vlan->vlan = (unsigned)ul;
            APPEND(vlans_incl, vlan, link);
            if (0 == ul)
                fprintf(stderr, "Warning: previous versions of %s "
                                "interpreted 0 as all VLANs. "
                                "If you want all VLANs now you must "
                                "specify %u.\n",
                    ProgramName, MAX_VLAN);
            break;
        case 'T':
            wanttcp = TRUE;
            break;
        case 'u':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0' || ul < 1U || ul > 65535U)
                usage("port must be an integer 1..65535");
            dns_port = (unsigned)ul;
            break;
        case 'm':
            u = 0;
            for (p = optarg; *p; p++)
                switch (*p) {
                case 'q':
                    u |= MSG_QUERY;
                    break;
                case 'u':
                    u |= MSG_UPDATE;
                    break;
                case 'n':
                    u |= MSG_NOTIFY;
                    break;
                default:
                    usage("-m takes only [qun]");
                }
            msg_wanted = u;
            break;
        case 's':
            u = 0;
            for (p = optarg; *p; p++)
                switch (*p) {
                case 'i':
                    u |= DIR_INITIATE;
                    break;
                case 'r':
                    u |= DIR_RESPONSE;
                    break;
                default:
                    usage("-s takes only [ir]");
                }
            dir_wanted = u;
            break;
        case 'h':
            u = 0;
            for (p = optarg; *p; p++)
                switch (*p) {
                case 'i':
                    u |= END_INITIATOR;
                    break;
                case 'r':
                    u |= END_RESPONDER;
                    break;
                default:
                    usage("-h takes only [ir]");
                }
            end_hide = u;
            break;
        case 'e':
            u = 0;
            for (p = optarg; *p; p++)
                switch (*p) {
                case 'n':
                    u |= ERR_NO;
                    break;
                case 'y':
                    u |= ERR_YES;
                    break;
                case 't':
                    u |= ERR_TRUNC;
                    break;
                case 'f':
                    u |= ERR_FORMERR;
                    break;
                case 's':
                    u |= ERR_SERVFAIL;
                    break;
                case 'x':
                    u |= ERR_NXDOMAIN;
                    break;
                case 'i':
                    u |= ERR_NOTIMPL;
                    break;
                case 'r':
                    u |= ERR_REFUSED;
                    break;
                default:
                    usage("-e takes only [nytfsxir]");
                }
            err_wanted = u;
            break;
        case 'a':
            endpoint_arg(&initiators, optarg);
            break;
        case 'z':
            endpoint_arg(&responders, optarg);
            break;
        case 'A':
            endpoint_arg(&not_initiators, optarg);
            break;
        case 'Z':
            endpoint_arg(&not_responders, optarg);
            break;
        case 'Y':
            endpoint_arg(&drop_responders, optarg);
            break;
        case 'w':
            dump_base = optarg;
            if (strcmp(optarg, "-") == 0)
                dump_type = to_stdout;
            else
                dump_type = to_file;
            break;
        case 'W':
            if (dump_suffix)
                free(dump_suffix);
            dump_suffix = strdup(optarg);
            check_gzip();
            break;
        case 'k':
            if (dump_type != to_file)
                usage("-k depends on -w"
                      " (note: can't be stdout)");
            kick_cmd = optarg;
            break;
        case 'F':
            if (!strcmp(optarg, "pcap")) {
                options.dump_format = pcap;
            } else if (!strcmp(optarg, "cbor")) {
                options.dump_format = cbor;
            } else if (!strcmp(optarg, "cds")) {
                options.dump_format = cds;
            } else {
                usage("invalid output format for -F");
            }
            break;
        case 't':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0')
                usage("argument to -t must be an integer");
            limit_seconds = (unsigned)ul;
            break;
        case 'c':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0')
                usage("argument to -c must be an integer");
            limit_packets = (unsigned)ul;
            break;
        case 'C':
            ul = strtoul(optarg, &p, 0);
            if (*p != '\0')
                usage("argument to -C must be an integer");
            limit_pcapfilesize = (unsigned)ul;
            break;
        case 'x':
        /* FALLTHROUGH */
        case 'X':
#if HAVE_NS_INITPARSE && HAVE_NS_PARSERR && HAVE_NS_SPRINTRR
        {
            int         i;
            myregex_ptr myregex = calloc(1, sizeof *myregex);
            assert(myregex != NULL);
            INIT_LINK(myregex, link);
            myregex->str = strdup(optarg);
            i            = regcomp(&myregex->reg, myregex->str, REGEX_CFLAGS);
            if (i != 0) {
                regerror(i, &myregex->reg,
                    errbuf, sizeof errbuf);
                usage(errbuf);
            }
            myregex->not = (ch == 'X');
            APPEND(myregexes, myregex, link);
        }
#else
            /*
             * -x and -X options require libbind because
             * the code calls ns_initparse(), ns_parserr(),
             * and ns_sprintrr()
             */
            fprintf(stderr, "%s must be compiled with libbind to use the -x or -X option.\n",
                ProgramName);
            exit(1);
#endif
        break;
        case 'B': {
            struct tm tm;
            memset(&tm, '\0', sizeof(tm));
            if (NULL == strptime(optarg, "%F %T", &tm))
                usage("--B arg must have format YYYY-MM-DD HH:MM:SS");
            start_time = xtimegm(&tm);
        } break;
        case 'E': {
            struct tm tm;
            memset(&tm, '\0', sizeof(tm));
            if (NULL == strptime(optarg, "%F %T", &tm))
                usage("--E arg must have format YYYY-MM-DD HH:MM:SS");
            stop_time = xtimegm(&tm);
        } break;
        case 'S':
            print_pcap_stats = TRUE;
            break;
        case 'P': {
            char*          fn = strdup(optarg);
            char*          t;
            char           sn[256];
            struct plugin* p = calloc(1, sizeof(*p));
            assert(p != NULL);
            INIT_LINK(p, link);
            t       = strrchr(fn, '/');
            p->name = strdup(t ? t + 1 : fn);
            if ((t = strstr(p->name, ".so")))
                *t    = 0;
            p->handle = dlopen(fn, RTLD_NOW);
            if (!p->handle) {
                logerr("%s: %s", fn, dlerror());
                exit(1);
            }
            snprintf(sn, sizeof(sn), "%s_start", p->name);
            p->start = dlsym(p->handle, sn);
            snprintf(sn, sizeof(sn), "%s_stop", p->name);
            p->stop = dlsym(p->handle, sn);
            snprintf(sn, sizeof(sn), "%s_open", p->name);
            p->open = dlsym(p->handle, sn);
            snprintf(sn, sizeof(sn), "%s_close", p->name);
            p->close = dlsym(p->handle, sn);
            snprintf(sn, sizeof(sn), "%s_output", p->name);
            p->output = dlsym(p->handle, sn);
            if (!p->output) {
                logerr("%s", dlerror());
                exit(1);
            }
            snprintf(sn, sizeof(sn), "%s_usage", p->name);
            p->usage = dlsym(p->handle, sn);
            snprintf(sn, sizeof(sn), "%s_extension", p->name);
            p->extension = dlsym(p->handle, sn);
            if (p->extension) {
                (*p->extension)(DNSCAP_EXT_IS_RESPONDER, (void*)is_responder);
                (*p->extension)(DNSCAP_EXT_IA_STR, (void*)_ia_str);
                (*p->extension)(DNSCAP_EXT_TCPSTATE_GETCURR, (void*)_tcpstate_getcurr);
                (*p->extension)(DNSCAP_EXT_TCPSTATE_RESET, (void*)_tcpstate_reset);
            }
            snprintf(sn, sizeof(sn), "%s_getopt", p->name);
            p->getopt = dlsym(p->handle, sn);
            if (p->getopt)
                (*p->getopt)(&argc, &argv);
            APPEND(plugins, p, link);
            if (dumptrace)
                fprintf(stderr, "Plugin '%s' loaded\n", p->name);
            free(fn);
        } break;
        case 'U':
            if (extra_bpf)
                free(extra_bpf);
            extra_bpf = strdup(optarg);
            break;
        case 'y':
#ifdef USE_SECCOMP
            use_seccomp = TRUE;
#else
            usage("seccomp-bpf not enabled");
#endif
            break;
        case 'M':
            monitor_mode = TRUE;
            break;
        case 'D':
            immediate_mode = TRUE;
            break;
        default:
            usage("unrecognized command line option");
        }
    }
    assert(msg_wanted != 0U);
    assert(err_wanted != 0U);
    if (dump_type != nowhere && options.use_layers)
        usage("use_layers is only compatible with -g so far");
    if (dump_type == nowhere && !preso && EMPTY(plugins))
        usage("without -w or -g, there would be no output");
    if (end_hide != 0U && wantfrags)
        usage("the -h and -f options are incompatible");
    if (!EMPTY(vlans_incl) && !EMPTY(vlans_excl))
        usage("the -L and -l options are mutually exclusive");
    if (background && (dumptrace || preso))
        usage("the -b option is incompatible with -d and -g");
    if (dumptrace >= 1) {
        endpoint_ptr ep;
        const char*  sep;
        myregex_ptr  mr;

        fprintf(stderr, "%s: version %s\n", ProgramName, PACKAGE_VERSION);
        fprintf(stderr,
            "%s: msg %c%c%c, side %c%c, hide %c%c, err %c%c%c%c%c%c%c%c, t %u, c %u, C %zu\n",
            ProgramName,
            (msg_wanted & MSG_QUERY) != 0 ? 'Q' : '.',
            (msg_wanted & MSG_UPDATE) != 0 ? 'U' : '.',
            (msg_wanted & MSG_NOTIFY) != 0 ? 'N' : '.',
            (dir_wanted & DIR_INITIATE) != 0 ? 'I' : '.',
            (dir_wanted & DIR_RESPONSE) != 0 ? 'R' : '.',
            (end_hide & END_INITIATOR) != 0 ? 'I' : '.',
            (end_hide & END_RESPONDER) != 0 ? 'R' : '.',
            (err_wanted & ERR_NO) != 0 ? 'N' : '.',
            (err_wanted & ERR_YES) == ERR_YES ? 'Y' : '.',
            (err_wanted & ERR_TRUNC) != 0 ? 't' : '.',
            (err_wanted & ERR_FORMERR) != 0 ? 'f' : '.',
            (err_wanted & ERR_SERVFAIL) != 0 ? 's' : '.',
            (err_wanted & ERR_NXDOMAIN) != 0 ? 'x' : '.',
            (err_wanted & ERR_NOTIMPL) != 0 ? 'i' : '.',
            (err_wanted & ERR_REFUSED) != 0 ? 'r' : '.',
            limit_seconds, limit_packets, limit_pcapfilesize);
        sep = "\tinit";
        for (ep = HEAD(initiators);
             ep != NULL;
             ep = NEXT(ep, link)) {
            fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
            sep = "";
        }
        if (!EMPTY(initiators))
            fprintf(stderr, "\n");
        sep = "\tresp";
        for (ep = HEAD(responders);
             ep != NULL;
             ep = NEXT(ep, link)) {
            fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
            sep = "";
        }
        if (!EMPTY(responders))
            fprintf(stderr, "\n");
        sep = "\t!init";
        for (ep = HEAD(not_initiators);
             ep != NULL;
             ep = NEXT(ep, link)) {
            fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
            sep = "";
        }
        if (!EMPTY(not_initiators))
            fprintf(stderr, "\n");
        sep = "\t!resp";
        for (ep = HEAD(not_responders);
             ep != NULL;
             ep = NEXT(ep, link)) {
            fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
            sep = "";
        }
        if (!EMPTY(not_responders))
            fprintf(stderr, "\n");
        sep = "\t!dropresp";
        for (ep = HEAD(drop_responders);
             ep != NULL;
             ep = NEXT(ep, link)) {
            fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
            sep = "";
        }
        if (!EMPTY(drop_responders))
            fprintf(stderr, "\n");
        if (!EMPTY(myregexes)) {
            fprintf(stderr, "%s: pat:", ProgramName);
            for (mr = HEAD(myregexes);
                 mr != NULL;
                 mr = NEXT(mr, link))
                fprintf(stderr, " %s/%s/",
                    mr->not? "!" : "", mr->str);
            fprintf(stderr, "\n");
        }
    }
    if (EMPTY(mypcaps)) {
        const char* name;
        name = pcap_lookupdev(errbuf);
        if (name == NULL) {
            fprintf(stderr, "%s: pcap_lookupdev: %s\n",
                ProgramName, errbuf);
            exit(1);
        }
        mypcap = calloc(1, sizeof *mypcap);
        assert(mypcap != NULL);
        INIT_LINK(mypcap, link);
        mypcap->name = (name == NULL) ? NULL : strdup(name);
        APPEND(mypcaps, mypcap, link);
    }
    if (start_time && stop_time && start_time >= stop_time)
        usage("start time must be before stop time");
    if ((start_time || stop_time) && NULL == dump_base)
        usage("--B and --E require -w");

    if (options.dump_format == cbor) {
        if (!have_cbor_support()) {
            usage("no built in cbor support");
        }
        cbor_set_size(options.cbor_chunk_size);
    } else if (options.dump_format == cds) {
        if (!have_cds_support()) {
            usage("no built in cds support");
        }
        cds_set_cbor_size(options.cds_cbor_size);
        cds_set_message_size(options.cds_message_size);
        cds_set_max_rlabels(options.cds_max_rlabels);
        cds_set_min_rlabel_size(options.cds_min_rlabel_size);
        if (options.cds_use_rdata_index && options.cds_use_rdata_rindex) {
            usage("can't use both CDS rdata index and rindex");
        }
        cds_set_use_rdata_index(options.cds_use_rdata_index);
        cds_set_use_rdata_rindex(options.cds_use_rdata_rindex);
        cds_set_rdata_index_min_size(options.cds_rdata_index_min_size);
        cds_set_rdata_rindex_min_size(options.cds_rdata_rindex_min_size);
        cds_set_rdata_rindex_size(options.cds_rdata_rindex_size);
    }

    if (!options.use_layers && (options.defrag_ipv4 || options.defrag_ipv6)) {
        usage("can't defragment IP packets without use_layers=yes");
    }

    if (options.reassemble_tcp_bfbparsedns) {
#if HAVE_NS_INITPARSE
        if (!options.reassemble_tcp) {
            usage("can't do byte for byte parsing of DNS without reassemble_tcp=yes");
        }
#else
        usage("not compiled with libbind, needed for reassemble_tcp_bfbparsedns=yes");
#endif
    }
}
