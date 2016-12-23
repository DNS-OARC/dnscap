/* dnscap - DNS capture utility
 *
 * By Paul Vixie (ISC) and Duane Wessels (Measurement Factory), 2007.
 */

/*
 * Copyright (c) 2016, OARC, Inc.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/fcntl.h>		/* for open() */
#include <sys/ioctl.h>		/* for TIOCNOTTY */
#include <stdarg.h>
#include <syslog.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/resource.h>
#if HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef __linux__
# define __FAVOR_BSD
# define __USE_GNU
# define _GNU_SOURCE
# include <net/ethernet.h>
#ifdef USE_SECCOMP
#include <seccomp.h>
#endif
#endif

#ifdef __FreeBSD__
# include <net/ethernet.h>
#endif

#ifdef __NetBSD__
# include <net/ethertypes.h>
# include <net/if.h>
# include <net/if_ether.h>
#endif

#ifdef __OpenBSD__
# include <net/ethertypes.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/in_var.h>
# include <netinet/if_ether.h>
#endif

#ifdef __APPLE__
# include <net/ethernet.h>
# include <net/bpf.h>
#endif

#ifdef __hpux
# include <net/if.h>
# include <netinet/if_ether.h>
# define ETHER_HDR_LEN ETHER_HLEN
# define __BIT_TYPES_DEFINED
# define __HPLX
#endif

#ifdef __SVR4
# include <stdarg.h>
# include <net/if.h>
# include <net/if_arp.h>
# include <netinet/if_ether.h>
# include "snprintf.h"
# define   IP_OFFMASK      0x1fff
# define u_int32_t uint32_t
# ifndef ETHER_HDR_LEN
#  define ETHER_HDR_LEN 14
# endif
#endif

#ifndef MY_BPFTIMEVAL
# define MY_BPFTIMEVAL timeval
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/nameser.h>
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pcap.h>
#include <regex.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "dnscap_common.h"
#include "dnscap.h"
#define ISC_CHECK_NONE 1
#include "isc/list.h"
#include "isc/assertions.h"
#include "dump_dns.h"
#include "dump_cbor.h"
#include "dump_cds.h"
#include "options.h"
#include "pcap-thread/pcap_thread.h"

#ifdef __linux__
extern char *strptime(const char *, const char *, struct tm *);
#endif

#define MY_GET32(l, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
} while (0)

/* Constants. */

#ifndef IPV6_VERSION
# define IPV6_VERSION		0x60
#endif
#ifndef IPV6_VERSION_MASK
# define IPV6_VERSION_MASK	0xf0
#endif

#define UDP10_QR_MASK	0x80
#define UDP10_QR_SHIFT	7
#define UDP10_OP_MASK	0x78
#define UDP10_OP_SHIFT	3
#define UDP10_AA_MASK	0x04
#define UDP10_AA_SHIFT	2
#define UDP10_TC_MASK	0x02
#define UDP10_TC_SHIFT	1
#define UDP10_RD_MASK	0x01
#define UDP10_RD_SHIFT	0

#define UDP11_RC_MASK	0x0f
#define UDP11_RC_SHIFT	0

#define MSG_QUERY	0x0001
#define MSG_UPDATE	0x0002
#define	MSG_NOTIFY	0x0004

#define ERR_TRUNC	0x0001
#define ERR_RCODE_BASE	0x0002
#define ERR_NO		(ERR_RCODE_BASE << ns_r_noerror)
#define ERR_FORMERR	(ERR_RCODE_BASE << ns_r_formerr)
#define ERR_SERVFAIL	(ERR_RCODE_BASE << ns_r_servfail)
#define ERR_NXDOMAIN	(ERR_RCODE_BASE << ns_r_nxdomain)
#define ERR_NOTIMPL	(ERR_RCODE_BASE << ns_r_notimpl)
#define ERR_REFUSED	(ERR_RCODE_BASE << ns_r_refused)
#define ERR_YES		(0xffffffff & ~ERR_NO)

#define END_INITIATOR	0x0001
#define END_RESPONDER	0x0002

#define HIDE_INET	0x7f7f7f7f
#define HIDE_INET6	"\177\177\177\177\177\177\177\177" \
			"\177\177\177\177\177\177\177\177"
#define HIDE_PORT	54321

#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN	0x8100
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86DD
#endif

#define THOUSAND	1000
#define MILLION		(THOUSAND*THOUSAND)
#define MAX_VLAN	4095
#define DNS_PORT	53
#define TO_MS		1
#define SNAPLEN		65536
#define TRUE		1
#define FALSE		0
#define REGEX_CFLAGS	(REG_EXTENDED|REG_ICASE|REG_NOSUB|REG_NEWLINE)
#define MAX_TCP_WINDOW	(0xFFFF << 14)
#define MEM_MAX		20000000000		/* SETTING MAX MEMORY USAGE TO 2GB */

/* Data structures. */

struct endpoint {
	LINK(struct endpoint)  link;
	iaddr			ia;
};
typedef struct endpoint *endpoint_ptr;
typedef LIST(struct endpoint) endpoint_list;

struct mypcap {
	LINK(struct mypcap)	link;
	const char *		name;
	struct pcap_stat	ps0, ps1;
	uint64_t            drops;
};
typedef struct mypcap *mypcap_ptr;
typedef LIST(struct mypcap) mypcap_list;

struct vlan {
	LINK(struct vlan)	link;
	unsigned		vlan;
};
typedef struct vlan *vlan_ptr;
typedef LIST(struct vlan) vlan_list;

struct text {
	LINK(struct text)	link;
	size_t			len;
	char *			text;
};
typedef struct text *text_ptr;
typedef LIST(struct text) text_list;
#define text_size(len) (sizeof(struct text) + len)

struct myregex {
	LINK(struct myregex)  link;
	regex_t			reg;
	char *			str;
	int			not;
};
typedef struct myregex *myregex_ptr;
typedef LIST(struct myregex) myregex_list;

struct tcpstate {
	LINK(struct tcpstate)  link;
	iaddr			saddr;
	iaddr			daddr;
	uint16_t		sport;
	uint16_t		dport;
	uint32_t		start;		/* seq# of tcp payload start */
	uint32_t		maxdiff;	/* maximum (seq# - start) */
	uint16_t		dnslen;
	time_t			last_use;
};
typedef struct tcpstate *tcpstate_ptr;
typedef LIST(struct tcpstate) tcpstate_list;

struct plugin {
	LINK(struct plugin)	link;
	char			*name;
	void			*handle;
	int			(*start)(logerr_t *);
	void			(*stop)();
	int			(*open)(my_bpftimeval);
	int			(*close)();
	output_t		(*output);
	void			(*getopt)(int *, char **[]);
	void			(*usage)();
};
LIST(struct plugin) plugins;

/* Forward. */

static void setsig(int, int);
static void usage(const char *) __attribute__((noreturn));
static void help_1(void);
static void help_2(void);
static void parse_args(int, char *[]);
static void endpoint_arg(endpoint_list *, const char *);
static void endpoint_add(endpoint_list *, iaddr);
static void prepare_bpft(void);
static int ep_present(const endpoint_list *, iaddr);
static size_t text_add(text_list *, const char *, ...);
static void text_free(text_list *);
static void open_pcaps(void);
static void poll_pcaps(void);
static void breakloop_pcaps(void);
static void close_pcaps(void);
static void dl_pkt(u_char *, const struct pcap_pkthdr *, const u_char *, const char*, const int);
static void network_pkt(const char *, my_bpftimeval, unsigned,
			const u_char *, size_t);
static output_t output;
static int dumper_open(my_bpftimeval);
static int dumper_close(my_bpftimeval);
static void sigclose(int);
static void sigbreak(int);
#if HAVE_PTHREAD
static void *sigthread(void * arg);
#endif
static uint16_t in_checksum(const u_char *, size_t);
static void daemonize(void);
static void drop_privileges(void);
static logerr_t logerr;
#if !HAVE___ASSERTION_FAILED
static void my_assertion_failed(const char *file, int line, assertion_type type, const char *msg, int something) __attribute__((noreturn));
#endif


/* Private data. */

static const char *ProgramName = "amnesia";
static int dumptrace = 0;
static int flush = FALSE;
static vlan_list vlans_excl;
static vlan_list vlans_incl;
static unsigned msg_wanted = MSG_QUERY;
static unsigned dir_wanted = DIR_INITIATE|DIR_RESPONSE;
static unsigned end_hide = 0U;
static unsigned err_wanted = ERR_NO | ERR_YES; /* accept all by default */
static tcpstate_list tcpstates;
static int tcpstate_count = 0;
static endpoint_list initiators, not_initiators;
static endpoint_list responders, not_responders;
static endpoint_list drop_responders;		/* drops only responses from these hosts */
static myregex_list myregexes;
static mypcap_list mypcaps;
static mypcap_ptr pcap_offline = NULL;
static const char *dump_base = NULL;
static char *dump_suffix = NULL;
static char *extra_bpf = NULL;
static enum {nowhere, to_stdout, to_file} dump_type = nowhere;
static enum {dumper_opened, dumper_closed} dump_state = dumper_closed;
static const char *kick_cmd = NULL;
static unsigned limit_seconds = 0U;
static time_t next_interval = 0;
static unsigned limit_packets = 0U;
static size_t limit_pcapfilesize = 0U;
static fd_set mypcap_fdset;
static int pcap_maxfd;
static pcap_t *pcap_dead;
static pcap_dumper_t *dumper;
static time_t dumpstart;
static unsigned msgcount;
static size_t capturedbytes = 0;
static char *dumpname, *dumpnamepart;
static char *bpft;
static unsigned dns_port = DNS_PORT;
static int promisc = TRUE;
static int monitor_mode = FALSE;
static int immediate_mode = FALSE;
static int background = FALSE;
static char errbuf[PCAP_ERRBUF_SIZE];
static int v6bug = FALSE;
static int wantfrags = FALSE;
static int wanticmp = FALSE;
static int wanttcp = FALSE;
static int preso = FALSE;
#ifdef USE_SECCOMP
static int use_seccomp = FALSE;
#endif
static int main_exit = FALSE;
static int alarm_set = FALSE;
static time_t start_time = 0;
static time_t stop_time = 0;
static int print_pcap_stats = FALSE;
static uint64_t pcap_drops = 0;
static my_bpftimeval last_ts = {0,0};
static unsigned long long mem_limit = (unsigned) MEM_MAX; /* process memory limit */
static int mem_limit_set = 1; /* TODO: Should be configurable */
const char DROPTOUSER[] = "nobody";
static pcap_thread_t pcap_thread = PCAP_THREAD_T_INIT;
static int only_offline_pcaps = TRUE;
static int dont_drop_privileges = FALSE;
static options_t options = OPTIONS_T_DEFAULTS;

/* Public. */

int
main(int argc, char *argv[]) {
	struct plugin *p;
	struct timeval now;
	res_init();
	parse_args(argc, argv);
	gettimeofday(&now, 0);
	if (start_time) {
		if (now.tv_sec < start_time) {
			char when[100];
			struct tm *tm = gmtime(&start_time);
			strftime(when, sizeof when, "%F %T", tm);
			fprintf(stderr, "Sleeping for %d seconds until %s UTC\n",
				(int) (start_time - now.tv_sec), when);
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

    /*
     * Defer signal setup until we have dropped privileges and daemonized,
     * otherwise signals might not reach us because different threads
     * are running under different users/access
     */
#if HAVE_PTHREAD
    {
        sigset_t set;
        int err;
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
		(void) dumper_close(last_ts);
	close_pcaps();
	for (p = HEAD(plugins); p != NULL; p = NEXT(p, link)) {
		if (p->stop)
			(*p->stop)();
	}
	options_free(&options);
	exit(0);
}

/* Private. */

static void
drop_privileges(void)
{
	struct rlimit rss;
	struct passwd pwd;
	struct passwd *result;
	size_t pwdBufSize;
	char *pwdBuf;
	unsigned int s;
	uid_t oldUID = getuid();
	uid_t oldGID = getgid();
	uid_t dropUID;
	gid_t dropGID;
	const char * user;
	struct group * grp = 0;

	/*
	 * Security: getting UID and GUID for nobody
	 */
	pwdBufSize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (pwdBufSize == -1)
		pwdBufSize = 16384;

	pwdBuf = calloc(pwdBufSize, sizeof(char));
	if (pwdBuf == NULL) {
		fprintf(stderr, "unable to allocate buffer for pwdBuf\n");
		exit(1);
	}

    user = options.user ? options.user : DROPTOUSER;
    if (options.group) {
        if (!(grp = getgrnam(options.group))) {
            if (errno) {
                fprintf(stderr, "Unable to get group %s: %s\n", options.group, strerror(errno));
            }
            else {
                fprintf(stderr, "Group %s not found, existing.\n", options.group);
            }
            exit(1);
        }
    }

	s = getpwnam_r(user, &pwd, pwdBuf, pwdBufSize, &result);
	if (result == NULL) {
		if (s == 0) {
			fprintf(stderr, "User %s not found, exiting.\n", user);
			exit(1);
		}else {
			fprintf(stderr, "issue with getpwnnam_r call, exiting.\n");
			exit(1);
		}
	}

	dropUID = pwd.pw_uid;
	dropGID = grp ? grp->gr_gid : pwd.pw_gid;
	memset(pwdBuf, 0, pwdBufSize);
	free(pwdBuf);

	/*
	 * Security section: setting memory limit and dropping privileges to nobody
	 */
	getrlimit(RLIMIT_DATA, &rss);
	if (mem_limit_set){
		rss.rlim_cur = mem_limit;
		rss.rlim_max = mem_limit;
		if (setrlimit(RLIMIT_DATA, &rss) == -1) {
			fprintf(stderr, "Unable to set the memory limit, exiting\n");
			exit(1);
		}
	}

#if HAVE_SETRESGID
	if (setresgid(dropGID, dropGID, dropGID) < 0) {
		fprintf(stderr, "Unable to drop GID to %s, exiting.\n", options.group ? options.group : user);
		exit(1);
	}
#elif HAVE_SETREGID
	if (setregid(dropGID, dropGID) < 0) {
		fprintf(stderr, "Unable to drop GID to %s, exiting.\n", options.group ? options.group : user);
		exit(1);
	}
#elif HAVE_SETEGID
	if (setegid(dropGID) < 0) {
		fprintf(stderr, "Unable to drop GID to %s, exiting.\n", options.group ? options.group : user);
		exit(1);
	}
#endif

#if HAVE_SETRESUID
	if (setresuid(dropUID, dropUID, dropUID) < 0) {
		fprintf(stderr, "Unable to drop UID to %s, exiting.\n", user);
		exit(1);
	}
#elif HAVE_SETREUID
	if (setreuid(dropUID, dropUID) < 0) {
		fprintf(stderr, "Unable to drop UID to %s, exiting.\n", user);
		exit(1);
	}
#elif HAVE_SETEUID
	if (seteuid(dropUID) < 0) {
		fprintf(stderr, "Unable to drop UID to %s, exiting.\n", user);
		exit(1);
	}
#endif

	/*
	 * Testing if privileges are dropped
	 */
	if (oldGID != getgid() && (setgid(oldGID) == 1 && setegid(oldGID) != 1)) {
		fprintf(stderr, "Able to restore back to root, exiting.\n");
		fprintf(stderr, "currentUID:%u currentGID:%u\n", getuid(), getgid());
		exit(1);
	}
	if ((oldUID != getuid() && getuid() == 0) && (setuid(oldUID) != 1 && seteuid(oldUID) != 1)) {
		fprintf(stderr, "Able to restore back to root, exiting.\n");
		fprintf(stderr, "currentUID:%u currentGID:%u\n", getgid(), getgid());
		exit(1);
	}

#ifdef USE_SECCOMP
	if(use_seccomp == FALSE) {
		return;
	}

	/*
	 * Setting SCMP_ACT_TRAP means the process will get
	 * a SIGSYS signal when a bad syscall is executed
	 * This is for debugging and should be monitored.
	 */
#if 0
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
#endif

	/*
	 * SCMP_ACT_KILL tells the kernel to kill the process
	 * when a syscall we did not filter on is called.
	 * This should be uncommented in production.
	 */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

	if(ctx == NULL) {
		fprintf(stderr, "Unable to create seccomp-bpf context\n");
		exit(1);
	}

	int r = 0;
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    r |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);

	if(r != 0) {
		fprintf(stderr, "Unable to apply seccomp-bpf filter\n");
		seccomp_release(ctx);
		exit(1);
	}

	r = seccomp_load(ctx);

	if(r < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "Unable to load seccomp-bpf filter\n");
		exit(1);
	}
#endif
}

#if !HAVE___ASSERTION_FAILED
static void
my_assertion_failed(const char *file, int line, assertion_type type, const char *msg, int something)
{
	(void) type;
	(void) something;
	fprintf(stderr, "assertion failed: %s(%d): %s\n", file, line, msg);
	abort();
}

assertion_failure_callback __assertion_failed = my_assertion_failed;
#endif

static const char *
version(void)
{
    return PACKAGE_VERSION;
}

static void
setsig(int sig, int oneshot) {
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	if (oneshot) {
		sa.sa_handler = sigbreak;
		sa.sa_flags = SA_RESETHAND;
	} else {
		sa.sa_handler = sigclose;
		sa.sa_flags = SA_RESTART;
	}
	if (sigaction(sig, &sa, NULL) < 0) {
		logerr("sigaction: %s", strerror(errno));
		exit(1);
	}
}

static time_t
xtimegm(struct tm *tmp)
{
#if defined (__SVR4) && defined (__sun)
	char tz[3]="TZ=";
	putenv((char *)tz);
	return mktime(tmp);
#else
	return timegm(tmp);
#endif
}

static void
usage(const char *msg) {
	struct plugin *p;
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

static void
help_1(void) {
	fprintf(stderr, "%s: version %s\n\n", ProgramName, version());
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

static void
help_2(void) {
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
        "  -P <plugin.so> load plugin, any argument after this is sent to the plugin!\n"
		);
}

static void
parse_args(int argc, char *argv[]) {
	mypcap_ptr mypcap;
	unsigned long ul;
	vlan_ptr vlan;
	unsigned u;
	int ch;
	char *p;

	if ((p = strrchr(argv[0], '/')) == NULL)
		ProgramName = argv[0];
	else
		ProgramName = p+1;
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
			"A:B:C:DE:F:IL:MNP:STU:VW:X:Y:Z:16?")
		) != EOF)
	{
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
			printf("%s version %s\n", ProgramName, version());
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
			vlan->vlan = (unsigned) ul;
			APPEND(vlans_excl, vlan, link);
			if (0 == ul)
				fprintf(stderr, "Warning: previous versions of %s "
					"interpreted 0 as all VLANs. "
					"If you want all VLANs now you must "
					"specify %u.\n", ProgramName, MAX_VLAN);
			break;
		case 'L':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0' || ul > MAX_VLAN)
				usage("vlan must be an integer 0..4095");
			vlan = calloc(1, sizeof *vlan);
			assert(vlan != NULL);
			INIT_LINK(vlan, link);
			vlan->vlan = (unsigned) ul;
			APPEND(vlans_incl, vlan, link);
			if (0 == ul)
				fprintf(stderr, "Warning: previous versions of %s "
					"interpreted 0 as all VLANs. "
					"If you want all VLANs now you must "
					"specify %u.\n", ProgramName, MAX_VLAN);
			break;
		case 'T':
			wanttcp = TRUE;
			break;
		case 'u':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0' || ul < 1U || ul > 65535U)
				usage("port must be an integer 1..65535");
			dns_port = (unsigned) ul;
			break;
		case 'm':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'q': u |= MSG_QUERY; break;
				case 'u': u |= MSG_UPDATE; break;
				case 'n': u |= MSG_NOTIFY; break;
				default: usage("-m takes only [qun]");
				}
			msg_wanted = u;
			break;
		case 's':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'i': u |= DIR_INITIATE; break;
				case 'r': u |= DIR_RESPONSE; break;
				default: usage("-s takes only [ir]");
				}
			dir_wanted = u;
			break;
		case 'h':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'i': u |= END_INITIATOR; break;
				case 'r': u |= END_RESPONDER; break;
				default: usage("-h takes only [ir]");
				}
			end_hide = u;
			break;
		case 'e':
			u = 0;
			for (p = optarg; *p; p++)
				switch (*p) {
				case 'n': u |= ERR_NO; break;
				case 'y': u |= ERR_YES; break;
				case 't': u |= ERR_TRUNC; break;
				case 'f': u |= ERR_FORMERR; break;
				case 's': u |= ERR_SERVFAIL; break;
				case 'x': u |= ERR_NXDOMAIN; break;
				case 'i': u |= ERR_NOTIMPL; break;
				case 'r': u |= ERR_REFUSED; break;
				default: usage("-e takes only [nytfsxir]");
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
		    }
		    else if (!strcmp(optarg, "cbor")) {
		        options.dump_format = cbor;
		    }
		    else if (!strcmp(optarg, "cds")) {
		        options.dump_format = cds;
		    }
		    else {
		        usage("invalid output format for -F");
		    }
		    break;
		case 't':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0')
				usage("argument to -t must be an integer");
			limit_seconds = (unsigned) ul;
			break;
		case 'c':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0')
				usage("argument to -c must be an integer");
			limit_packets = (unsigned) ul;
			break;
		case 'C':
			ul = strtoul(optarg, &p, 0);
			if (*p != '\0')
				usage("argument to -C must be an integer");
			limit_pcapfilesize = (unsigned) ul;
			break;
		case 'x':
			/* FALLTHROUGH */
		case 'X':
#if HAVE_NS_INITPARSE && HAVE_NS_PARSERR && HAVE_NS_SPRINTRR
			{
				int i;
				myregex_ptr myregex = calloc(1, sizeof *myregex);
				assert(myregex != NULL);
				INIT_LINK(myregex, link);
				myregex->str = strdup(optarg);
				i = regcomp(&myregex->reg, myregex->str, REGEX_CFLAGS);
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
		case 'B':
			{
				struct tm tm;
				memset(&tm, '\0', sizeof(tm));
				if (NULL == strptime(optarg, "%F %T", &tm))
					usage("--B arg must have format YYYY-MM-DD HH:MM:SS");
				start_time = xtimegm(&tm);
			}
			break;
		case 'E':
			{
				struct tm tm;
				memset(&tm, '\0', sizeof(tm));
				if (NULL == strptime(optarg, "%F %T", &tm))
					usage("--E arg must have format YYYY-MM-DD HH:MM:SS");
				stop_time = xtimegm(&tm);
			}
			break;
		case 'S':
			print_pcap_stats = TRUE;
			break;
		case 'P':
			{
				char *fn = strdup(optarg);
				char *t;
				char sn[256];
				struct plugin *p = calloc(1, sizeof(*p));
				assert(p != NULL);
				INIT_LINK(p, link);
				t = strrchr(fn, '/');
				p->name = strdup(t ? t+1 : fn);
				if ((t = strstr(p->name, ".so")))
					*t = 0;
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
				snprintf(sn, sizeof(sn), "%s_getopt", p->name);
				p->getopt = dlsym(p->handle, sn);
				if (p->getopt)
					(*p->getopt)(&argc, &argv);
				APPEND(plugins, p, link);
				if (dumptrace)
					fprintf(stderr, "Plugin '%s' loaded\n", p->name);
			    free(fn);
			}
			break;
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
		const char *sep;
		myregex_ptr mr;

		fprintf(stderr, "%s: version %s\n", ProgramName, version());
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
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(initiators))
			fprintf(stderr, "\n");
		sep = "\tresp";
		for (ep = HEAD(responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(responders))
			fprintf(stderr, "\n");
		sep = "\t!init";
		for (ep = HEAD(not_initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(not_initiators))
			fprintf(stderr, "\n");
		sep = "\t!resp";
		for (ep = HEAD(not_responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			fprintf(stderr, "%s %s", sep, ia_str(ep->ia));
			sep = "";
		}
		if (!EMPTY(not_responders))
			fprintf(stderr, "\n");
		sep = "\t!dropresp";
		for (ep = HEAD(drop_responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
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
					mr->not ? "!" : "", mr->str);
			fprintf(stderr, "\n");
		}
	}
	if (EMPTY(mypcaps)) {
		const char *name;
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
    }
    else if (options.dump_format == cds) {
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
}

static void
endpoint_arg(endpoint_list *list, const char *arg) {
	struct addrinfo *ai;
	iaddr ia;
	void *p;

	if (inet_pton(AF_INET6, arg, &ia.u.a6) > 0) {
		ia.af = AF_INET6;
		endpoint_add(list, ia);
	} else if (inet_pton(AF_INET, arg, &ia.u.a4) > 0) {
		ia.af = AF_INET;
		endpoint_add(list, ia);
	} else if (getaddrinfo(arg, NULL, NULL, &ai) == 0) {
		struct addrinfo *a;

		for (a = ai; a != NULL; a = a->ai_next) {
			if (a->ai_socktype != SOCK_DGRAM)
				continue;
			switch (a->ai_family) {
			case PF_INET:
				ia.af = AF_INET;
				p = &((struct sockaddr_in *)a->ai_addr)
					->sin_addr;
				memcpy(&ia.u.a4, p, sizeof ia.u.a4);
				break;
			case PF_INET6:
				ia.af = AF_INET6;
				p = &((struct sockaddr_in6 *)a->ai_addr)
					->sin6_addr;
				memcpy(&ia.u.a6, p, sizeof ia.u.a6);
				break;
			default:
				continue;
			}
			endpoint_add(list, ia);
		}
		freeaddrinfo(ai);
	} else
		usage("invalid host address");
}

static void
endpoint_add(endpoint_list *list, iaddr ia) {
	endpoint_ptr ep;

	ep = calloc(1, sizeof *ep);
	assert(ep != NULL);
	INIT_LINK(ep, link);
	ep->ia = ia;
	APPEND(*list, ep, link);
}

static void
prepare_bpft(void) {
	unsigned udp10_mbs, udp10_mbc, udp11_mbs, udp11_mbc;
	text_list bpfl;
	text_ptr text;
	size_t len;

	/* Prepare the must-be-set and must-be-clear tests. */
	udp10_mbs = udp10_mbc = udp11_mbs = udp11_mbc = 0U;
	if ((dir_wanted & DIR_INITIATE) != 0) {
		if ((dir_wanted & DIR_RESPONSE) == 0)
			udp10_mbc |= UDP10_QR_MASK;
	} else if ((dir_wanted & DIR_RESPONSE) != 0) {
		udp10_mbs |= UDP10_QR_MASK;
	}
	if ((msg_wanted & MSG_UPDATE) != 0) {
		if ((msg_wanted & (MSG_QUERY|MSG_NOTIFY)) == 0)
			udp10_mbs |= (ns_o_update << UDP10_OP_SHIFT);
	} else if ((msg_wanted & MSG_NOTIFY) != 0) {
		if ((msg_wanted & (MSG_QUERY|MSG_UPDATE)) == 0)
			udp10_mbs |= (ns_o_notify << UDP10_OP_SHIFT);
	} else if ((msg_wanted & MSG_QUERY) != 0) {
		udp10_mbc |= UDP10_OP_MASK;
	}
	if (err_wanted == ERR_NO) {
		udp10_mbc |= UDP10_TC_MASK;
		udp11_mbc |= UDP11_RC_MASK;
	}

/*
 * Model
 * (vlan) and (transport)
 * (vlan) and ((icmp) or (frags) or (dns))
 * (vlan) and ((icmp) or (frags) or ((ports) and (hosts)))
 * (vlan) and ((icmp) or (frags) or (((tcp) or (udp)) and (hosts)))
 * [(vlan) and] ( [(icmp) or] [(frags) or] ( ( [(tcp) or] (udp) ) [and (hosts)] ) )
 */

	/* Make a BPF program to do early course kernel-level filtering. */
	INIT_LIST(bpfl);
	len = 0;
	if (!EMPTY(vlans_excl))
		len += text_add(&bpfl, "vlan and ");
	len += text_add(&bpfl, "( ");	 /* ( transports ...  */
	if (wanticmp) {
		len += text_add(&bpfl, "( ip proto 1 or ip proto 58 ) or ");
	}
	if (wantfrags) {
		len += text_add(&bpfl, "( ip[6:2] & 0x1fff != 0 or ip6[6] = 44 ) or ");
	}
	len += text_add(&bpfl, "( ");	/* ( dns ...  */
	len += text_add(&bpfl, "( ");	/* ( ports ...  */
	if (wanttcp) {
		len += text_add(&bpfl, "( tcp port %d ) or ", dns_port);
		/* tcp packets can be filtered by initiators/responders, but
		 * not mbs/mbc. */
	}
	len += text_add(&bpfl, "( udp port %d", dns_port);
	if (!v6bug) {
		if (udp10_mbc != 0)
			len += text_add(&bpfl, " and udp[10] & 0x%x = 0",
					udp10_mbc);
		if (udp10_mbs != 0)
			len += text_add(&bpfl, " and udp[10] & 0x%x = 0x%x",
					udp10_mbs, udp10_mbs);
		if (udp11_mbc != 0)
			len += text_add(&bpfl, " and udp[11] & 0x%x = 0",
					udp11_mbc);
/* Dead code, udp11_mbs never set
		if (udp11_mbs != 0)
			len += text_add(&bpfl, " and udp[11] & 0x%x = 0x%x",
					udp11_mbs, udp11_mbs);
*/

		if (err_wanted != ERR_NO) {
			len += text_add(&bpfl, " and (");
			if ((err_wanted & ERR_TRUNC) != 0) {
				len += text_add(&bpfl,
						"udp[10] & 0x%x = 0x%x or ",
						UDP10_TC_MASK, UDP10_TC_MASK);
			}
			len += text_add(&bpfl,
					"0x%x << (udp[11] & 0xf) & 0x%x != 0) ",
					ERR_RCODE_BASE, err_wanted);
		}
	}
	len += text_add(&bpfl, ") ");	/*  ... udp 53 ) */
	len += text_add(&bpfl, ") ");	/*  ... ports ) */
	if (!EMPTY(initiators) ||
	    !EMPTY(responders))
	{
		const char *or = "or", *lp = "(", *sep;
		endpoint_ptr ep;

		len += text_add(&bpfl, " and host");
		sep = lp;
		for (ep = HEAD(initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		for (ep = HEAD(responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		len += text_add(&bpfl, " )");
	}
	if (!EMPTY(not_initiators) ||
	    !EMPTY(not_responders))
	{
		const char *or = "or", *lp = "(", *sep;
		endpoint_ptr ep;

		len += text_add(&bpfl, " and not host");
		sep = lp;
		for (ep = HEAD(not_initiators);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		for (ep = HEAD(not_responders);
		     ep != NULL;
		     ep = NEXT(ep, link))
		{
			len += text_add(&bpfl, " %s %s", sep, ia_str(ep->ia));
			sep = or;
		}
		len += text_add(&bpfl, " )");
	}
	len += text_add(&bpfl, ") ");	/*  ... dns ) */
	len += text_add(&bpfl, ")"); 	/* ... transport ) */
	if (extra_bpf)
		len += text_add(&bpfl, " and ( %s )", extra_bpf);

	bpft = calloc(len + 1, sizeof(char));
	assert(bpft != NULL);
	for (text = HEAD(bpfl);
	     text != NULL;
	     text = NEXT(text, link))
		strcat(bpft, text->text);
	text_free(&bpfl);
    if (!EMPTY(vlans_incl)) {
        static char *bpft_vlan;
        len = 2*strlen(bpft) + strlen("() or (vlan and ())");
        bpft_vlan = calloc(len + 1, sizeof(char));
        assert(bpft_vlan != NULL);
        sprintf(bpft_vlan, "(%s) or (vlan and (%s))", bpft, bpft);
        bpft = realloc(bpft, len + 1);
        assert(bpft != NULL);
        strcpy(bpft, bpft_vlan);
        free(bpft_vlan);
    }
	if (dumptrace >= 1)
		fprintf(stderr, "%s: \"%s\"\n", ProgramName, bpft);
}

const char *
ia_str(iaddr ia) {
	static char ret[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

	(void) inet_ntop(ia.af, &ia.u, ret, sizeof ret);
	return (ret);
}

static int
ia_equal(iaddr x, iaddr y) {
	if (x.af != y.af)
		return FALSE;
	switch (x.af) {
	case AF_INET:
		return (x.u.a4.s_addr == y.u.a4.s_addr);
	case AF_INET6:
		return (memcmp(&x.u.a6, &y.u.a6, sizeof x.u.a6) == 0);
	}
	return FALSE;
}

static int
ep_present(const endpoint_list *list, iaddr ia) {
	endpoint_ptr ep;

	for (ep = HEAD(*list);
	     ep != NULL;
	     ep = NEXT(ep, link))
		if (ia_equal(ia, ep->ia))
			return TRUE;
	return (FALSE);
}

static size_t
text_add(text_list *list, const char *fmt, ...) {
	text_ptr text;
	va_list ap;
	int len;

	text = calloc(1, sizeof *text);
	assert(text != NULL);
	INIT_LINK(text, link);
	va_start(ap, fmt);
	len = vasprintf(&text->text, fmt, ap);
	assert(len >= 0);
	va_end(ap);
	APPEND(*list, text, link);
	return (len);
}

static void
text_free(text_list *list) {
	text_ptr text;

	while ((text = HEAD(*list)) != NULL) {
		UNLINK(*list, text, link);
		free(text);
	}
}

static void
drop_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt, const char* name, const int dlt) {
	mypcap_ptr mypcap = (mypcap_ptr) user;

    pcap_drops++;
    if (mypcap) {
        mypcap->drops++;
    }
}

static void
open_pcaps(void) {
	mypcap_ptr mypcap;
	int err;

    pcap_thread_set_snaplen(&pcap_thread, SNAPLEN);
    pcap_thread_set_promiscuous(&pcap_thread, promisc);
    pcap_thread_set_monitor(&pcap_thread, monitor_mode);
    pcap_thread_set_immediate_mode(&pcap_thread, immediate_mode);
    pcap_thread_set_callback(&pcap_thread, dl_pkt);
    pcap_thread_set_dropback(&pcap_thread, drop_pkt);
    pcap_thread_set_filter(&pcap_thread, bpft, strlen(bpft));

	assert(!EMPTY(mypcaps));
	for (mypcap = HEAD(mypcaps);
	     mypcap != NULL;
	     mypcap = NEXT(mypcap, link))
	{
        if (pcap_offline)
            err = pcap_thread_open_offline(&pcap_thread, mypcap->name, (u_char*)mypcap);
        else
            err = pcap_thread_open(&pcap_thread, mypcap->name, (u_char*)mypcap);

        if (err == PCAP_THREAD_EPCAP) {
            fprintf(stderr, "%s: pcap_thread libpcap error [%d]: %s (%s)\n",
                ProgramName,
                pcap_thread_status(&pcap_thread),
                pcap_statustostr(pcap_thread_status(&pcap_thread)),
                pcap_thread_errbuf(&pcap_thread)
            );
            exit(1);
        }
        if (err) {
            fprintf(stderr, "%s: pcap_thread error [%d]: %s\n",
                ProgramName,
                err,
                pcap_thread_strerr(err)
            );
            exit(1);
        }
	}
	pcap_dead = pcap_open_dead(DLT_RAW, SNAPLEN);
}

static void
poll_pcaps(void) {
    pcap_thread_run(&pcap_thread);
    main_exit = TRUE;
}

static void
breakloop_pcaps(void) {
    pcap_thread_stop(&pcap_thread);
}

static void
close_pcaps(void) {
    pcap_thread_close(&pcap_thread);
}

#define MAX_TCP_IDLE_TIME	600
#define MAX_TCP_IDLE_COUNT	4096
#define TCP_GC_TIME		60

static tcpstate_ptr
tcpstate_find(iaddr from, iaddr to, unsigned sport, unsigned dport, time_t t) {
	static time_t next_gc = 0;
	tcpstate_ptr tcpstate;

	for (tcpstate = HEAD(tcpstates);
	     tcpstate != NULL;
	     tcpstate = NEXT(tcpstate, link))
	{
		if (ia_equal(tcpstate->saddr, from) &&
		    ia_equal(tcpstate->daddr, to) &&
		    tcpstate->sport == sport &&
		    tcpstate->dport == dport)
			break;
	}
	if (tcpstate != NULL) {
		tcpstate->last_use = t;
		if (tcpstate != HEAD(tcpstates)) {
			/* move to beginning of list */
			UNLINK(tcpstates, tcpstate, link);
			PREPEND(tcpstates, tcpstate, link);
		}
	}

	if (t >= next_gc || tcpstate_count > MAX_TCP_IDLE_COUNT) {
		/* garbage collect stale states */
		time_t min_last_use = t - MAX_TCP_IDLE_TIME;
		while ((tcpstate = TAIL(tcpstates)) &&
		    tcpstate->last_use < min_last_use)
		{
			UNLINK(tcpstates, tcpstate, link);
			tcpstate_count--;
		}
		next_gc = t + TCP_GC_TIME;
	}

	return tcpstate;
}

static tcpstate_ptr
tcpstate_new(iaddr from, iaddr to, unsigned sport, unsigned dport) {

	tcpstate_ptr tcpstate = calloc(1, sizeof *tcpstate);
	if (tcpstate == NULL) {
	    /* Out of memory; recycle the least recently used */
	    logerr("warning: out of memory, "
		"discarding some TCP state early");
	    tcpstate = TAIL(tcpstates);
	    assert(tcpstate != NULL);
	} else {
	    tcpstate_count++;
	}
	tcpstate->saddr = from;
	tcpstate->daddr = to;
	tcpstate->sport = sport;
	tcpstate->dport = dport;
	INIT_LINK(tcpstate, link);
	PREPEND(tcpstates, tcpstate, link);
	return tcpstate;
}

static void
dl_pkt(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt, const char* name, const int dlt) {
	mypcap_ptr mypcap = (mypcap_ptr) user;
	size_t len = hdr->caplen;
	unsigned etype, vlan, pf;
	char descr[200];

	last_ts = hdr->ts;
	if (stop_time != 0 && hdr->ts.tv_sec >= stop_time) {
		breakloop_pcaps();
		main_exit = TRUE;
	}

	if (main_exit)
		return;

	/* If ever SNAPLEN wasn't big enough, we have no recourse. */
	if (hdr->len != hdr->caplen)
		return;

	/* Data link. */
	vlan = MAX_VLAN;	/* MAX_VLAN (0xFFF) is reserved and shouldn't appear on the wire */
	switch (dlt) {
	case DLT_NULL: {
		uint32_t x;

		if (len < NS_INT32SZ)
			return;
		x = *(const uint32_t *)pkt;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		pkt += NS_INT32SZ;
		len -= NS_INT32SZ;
		break;
	    }
	case DLT_LOOP: {
		uint32_t x;

		if (len < NS_INT32SZ)
			return;
		MY_GET32(x, pkt);
		len -= NS_INT32SZ;
		if (x == PF_INET)
			etype = ETHERTYPE_IP;
		else if (x == PF_INET6)
			etype = ETHERTYPE_IPV6;
		else
			return;
		break;
	    }
	case DLT_RAW: {
		if (len < 1)
			return;
		switch (*(const uint8_t *)pkt >> 4) {
		case 4:
			etype = ETHERTYPE_IP;
			break;
		case 6:
			etype = ETHERTYPE_IPV6;
			break;
		default:
			return;
		}
		break;
	    }
	case DLT_EN10MB: {
		const struct ether_header *ether;

		if (len < ETHER_HDR_LEN)
			return;
		ether = (const struct ether_header *) pkt;
		etype = ntohs(ether->ether_type);
		pkt += ETHER_HDR_LEN;
		len -= ETHER_HDR_LEN;
		if (etype == ETHERTYPE_VLAN) {
			if (len < 4)
				return;
			vlan = ntohs(*(const uint16_t *) pkt) & 0xFFF;
			pkt += 2;
			len -= 2;
			etype = ntohs(*(const uint16_t *) pkt);
			pkt += 2;
			len -= 2;
		}
		break;
	    }
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL: {
		if (len < 16)
			return;
		etype = ntohs(*(const uint16_t *) &pkt[14]);
		pkt += 16;
		len -= 16;
		break;
	    }
#endif
	default:
		return;
	}

	if (!EMPTY(vlans_excl)) {
		vlan_ptr vl;

		for (vl = HEAD(vlans_excl);
		     vl != NULL;
		     vl = NEXT(vl, link))
			if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
				break;
        /*
         * If there is no VLAN matching the packet, skip it
         */
		if (vl == NULL)
			return;
	}
	else if (!EMPTY(vlans_incl)) {
		vlan_ptr vl;

		for (vl = HEAD(vlans_incl);
		     vl != NULL;
		     vl = NEXT(vl, link))
			if (vl->vlan == vlan || vl->vlan == MAX_VLAN)
				break;
        /*
         * If there is no VLAN matching the packet, and the packet is tagged, skip it
         */
		if (vl == NULL && vlan != MAX_VLAN)
			return;
	}

	switch (etype) {
	case ETHERTYPE_IP:
		pf = PF_INET;
		break;
	case ETHERTYPE_IPV6:
		pf = PF_INET6;
		break;
	default:
		return;
	}

	if (preso) {
		char when[100], via[100];
		const struct tm *tm;
		time_t t;

		t = (time_t) hdr->ts.tv_sec;
		tm = gmtime(&t);
		strftime(when, sizeof when, "%Y-%m-%d %T", tm);
		strcpy(via, (mypcap->name == NULL)
				? "\"some interface\""
				: mypcap->name);
		if (vlan != MAX_VLAN)
			sprintf(via + strlen(via), " (vlan %u)", vlan);
		sprintf(descr, "[%lu] %s.%06lu [#%ld %s %u] \\\n",
			(u_long)len, when, (u_long)hdr->ts.tv_usec,
			(long)msgcount, via, vlan);
	} else {
		descr[0] = '\0';
	}

	if (next_interval != 0 && hdr->ts.tv_sec >= next_interval && dumper_opened == dump_state)
		dumper_close(hdr->ts);
	if (dumper_closed == dump_state && dumper_open(hdr->ts))
		goto breakloop;

	network_pkt(descr, hdr->ts, pf, pkt, len);

	if (limit_packets != 0U && msgcount == limit_packets) {
		if (preso)
			goto breakloop;
		if (dumper_opened == dump_state && dumper_close(hdr->ts))
			goto breakloop;
		msgcount = 0;
	}

	if (limit_pcapfilesize != 0U && capturedbytes >= limit_pcapfilesize) {
		if (preso) {
			goto breakloop;
		}
		if (dumper_opened == dump_state && dumper_close(hdr->ts)) {
			goto breakloop;
		}
		capturedbytes = 0;
	}

	return;
 breakloop:
	breakloop_pcaps();
	main_exit = TRUE;
}

/* Discard this packet.  If it's part of TCP stream, all subsequent pkts on
 * the same tcp stream will also be discarded. */
static void
discard(tcpstate_ptr tcpstate, const char *msg)
{
	if (dumptrace >= 3 && msg)
		fprintf(stderr, "discarding packet: %s\n", msg);
	if (tcpstate) {
		UNLINK(tcpstates, tcpstate, link);
		free(tcpstate);
		tcpstate_count--;
		return;
	}
}

static void
network_pkt(const char *descr, my_bpftimeval ts, unsigned pf,
	    const u_char *opkt, size_t olen)
{
	u_char pkt_copy[SNAPLEN], *pkt = pkt_copy;
	const u_char *dnspkt;
	unsigned proto, sport, dport;
	iaddr from, to, initiator, responder;
	struct ip6_hdr *ipv6;
	int response;
	unsigned flags = 0;
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;
	tcpstate_ptr tcpstate = NULL;
	struct ip *ip;
	size_t len, dnslen;
	HEADER dns;

	if (dumptrace >= 4)
		fprintf(stderr, "processing %s packet: len=%zu\n", (pf==PF_INET?"IPv4":(pf==PF_INET6?"IPv6":"unknown")), olen);

	/* Make a writable copy of the packet and use that copy from now on. */
	memcpy(pkt, opkt, len = olen);

	/* Network. */
	ip = NULL;
	ipv6 = NULL;
	sport = dport = 0;
	switch (pf) {
	case PF_INET: {
		unsigned offset;

		if (len < sizeof *ip)
			return;
		ip = (void *) pkt;
		if (ip->ip_v != IPVERSION)
			return;
		proto = ip->ip_p;
		memset(&from, 0, sizeof from);
		from.af = AF_INET;
		memcpy(&from.u.a4, &ip->ip_src, sizeof(struct in_addr));
		memset(&to, 0, sizeof to);
		to.af = AF_INET;
		memcpy(&to.u.a4, &ip->ip_dst, sizeof(struct in_addr));
		offset = ip->ip_hl << 2;
		if (len > ip->ip_len)	/* small IP packets have L2 padding */
			len = ip->ip_len;
		if (len <= (size_t) offset)
			return;
		pkt += offset;
		len -= offset;
		offset = ntohs(ip->ip_off);
		if ((offset & IP_MF) != 0 ||
		    (offset & IP_OFFMASK) != 0)
		{
			if (wantfrags) {
				flags |= DNSCAP_OUTPUT_ISFRAG;
				output(descr, from, to, ip->ip_p, flags, sport, dport, ts, pkt_copy, olen, NULL, 0);
				return;
			}
			return;
		}
		break;
	    }
	case PF_INET6: {
		uint16_t payload_len;
		uint8_t nexthdr;
		unsigned offset;

		if (len < sizeof *ipv6)
			return;
		ipv6 = (void *) pkt;
		if ((ipv6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return;

		nexthdr = ipv6->ip6_nxt;
		offset = sizeof(struct ip6_hdr);
		payload_len = ntohs(ipv6->ip6_plen);

		memset(&from, 0, sizeof from);
		from.af = AF_INET6;
		memcpy(&from.u.a6, &ipv6->ip6_src, sizeof(struct in6_addr));
		memset(&to, 0, sizeof to);
		to.af = AF_INET6;
		memcpy(&to.u.a6, &ipv6->ip6_dst, sizeof(struct in6_addr));

                while (nexthdr == IPPROTO_ROUTING ||	/* routing header */
		       nexthdr == IPPROTO_HOPOPTS ||	/* Hop-by-Hop opts */
		       nexthdr == IPPROTO_FRAGMENT ||	/* fragmentation hdr */
		       nexthdr == IPPROTO_DSTOPTS ||	/* destination opts */
		       nexthdr == IPPROTO_AH ||		/* destination opts */
		       nexthdr == IPPROTO_ESP)		/* encap sec payload */
		{
			struct {
				uint8_t nexthdr;
				uint8_t length;
			} ext_hdr;
			uint16_t ext_hdr_len;

			/* Catch broken packets */
			if ((offset + sizeof ext_hdr) > len)
				return;

			/* Cannot handle fragments. */
			if (nexthdr == IPPROTO_FRAGMENT) {
				if (wantfrags) {
					flags |= DNSCAP_OUTPUT_ISFRAG;
					output(descr, from, to, IPPROTO_FRAGMENT, flags, sport, dport, ts, pkt_copy, olen, NULL, 0);
					return;
				}
				return;
			}

			memcpy(&ext_hdr, (u_char *)ipv6 + offset,
			       sizeof ext_hdr);
			nexthdr = ext_hdr.nexthdr;
			ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

			if (ext_hdr_len > payload_len)
				return;

			offset += ext_hdr_len;
			payload_len -= ext_hdr_len;
		}

		if ((offset + payload_len) > len || payload_len == 0)
			return;

		proto = nexthdr;
		pkt += offset;
		len -= offset;
		break;
	    }
	default:
		return;
	}

	/* Transport. */
	switch (proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		output(descr, from, to, proto, flags, sport, dport, ts, pkt_copy, olen, pkt, len);
		return;
	case IPPROTO_UDP: {
		if (len < sizeof *udp)
			return;
		udp = (void *) pkt;
		switch (from.af) {
		case AF_INET:
		case AF_INET6:
			sport = ntohs(udp->uh_sport);
			dport = ntohs(udp->uh_dport);
			break;
		default:
			abort();
		}
		pkt += sizeof *udp;
		len -= sizeof *udp;
		dnspkt = pkt;
		dnslen = len;
		flags |= DNSCAP_OUTPUT_ISDNS;
		break;
	}
	case IPPROTO_TCP: {
		/* TCP processing.
		 * We need to capture enough to allow a later analysis to
		 * reassemble the TCP stream, but we don't want to keep all
		 * the state required to do reassembly here.
		 * When we get a SYN, we don't yet know if the DNS message
		 * will pass the filters, so we always output it, and also
		 * generate a tcpstate to keep track of the stream.  (An
		 * alternative would be to store the SYN packet on the
		 * tcpstate and not output it until a later packet passes the
		 * filter, but that would require more memory and would
		 * reorder packets in the pcap output.)
		 * When we get the _first_ DNS header on the stream, then we
		 * can apply the DNS header filters; if the packet passes, we
		 * output the packet and keep the tcpstate; if it fails, we
		 * discard the packet and the tcpstate.
		 * When we get any other packet with DNS payload, we output it
		 * only if there is a corresponding tcpstate indicating that
		 * the header passed the filters.
		 * Packets with no TCP payload (e.g., packets containing only
		 * an ACK) are discarded, since they carry no DNS information
		 * and are not needed for stream reassembly.
		 * FIN packets are always output to match the SYN, even if the
		 * DNS header failed the filter, to be friendly to later
		 * analysis programs that allocate state for each SYN.
		 * -- kkeys@caida.org
		 */
		unsigned offset;
		uint32_t seq;
		if (!wanttcp)
		    return;
		if (len < sizeof *tcp)
			return;
		tcp = (void *) pkt;
		switch (from.af) {
		case AF_INET:
		case AF_INET6:
			sport = ntohs(tcp->th_sport);
			dport = ntohs(tcp->th_dport);
			seq = ntohl(tcp->th_seq);
			break;
		default:
			abort();
		}
		offset = tcp->th_off * 4;
		pkt += offset;
		len -= offset;
#if 1
		tcpstate = tcpstate_find(from, to, sport, dport, ts.tv_sec);
		if (dumptrace >= 3) {
			fprintf(stderr, "%s: tcp pkt: %lu.%06lu [%4lu] ", ProgramName,
			    (u_long)ts.tv_sec, (u_long)ts.tv_usec, (u_long)len);
			fprintf(stderr, "%15s -> ", ia_str(from));
			fprintf(stderr, "%15s; ", ia_str(to));
			if (tcpstate)
			    fprintf(stderr, "want=%08x; ", tcpstate->start);
			else
			    fprintf(stderr, "no state; ");
			fprintf(stderr, "seq=%08x; ", seq);
		}
		if (tcp->th_flags & (TH_FIN | TH_RST)) {
		    /* Always output FIN and RST segments. */
		    if (dumptrace >= 3)
			fprintf(stderr, "FIN|RST\n");
		    output(descr, from, to, proto, flags, sport, dport, ts,
			pkt_copy, olen, NULL, 0);
		    /* End of stream; deallocate the tcpstate. */
		    if (tcpstate) {
			UNLINK(tcpstates, tcpstate, link);
			free(tcpstate);
			tcpstate_count--;
		    }
		    return;
		}
		if (tcp->th_flags & TH_SYN) {
		    if (dumptrace >= 3)
			fprintf(stderr, "SYN\n");
		    /* Always output SYN segments. */
		    output(descr, from, to, proto, flags, sport, dport, ts,
			pkt_copy, olen, NULL, 0);
		    if (tcpstate) {
#if 0
			/* Disabled because warning may scare user, and
			 * there's nothing else we can do anyway. */
			if (tcpstate->start == seq + 1) {
			    /* repeated SYN */
			} else {
			    /* Assume existing state is stale and recycle it. */
			    if (ts.tv_sec - tcpstate->last_use < MAX_TCP_IDLE_TIME)
				fprintf(stderr, "warning: recycling state for "
				    "duplicate tcp stream after only %ld "
				    "seconds idle\n",
				    (u_long)(ts.tv_sec - tcpstate->last_use));
			}
#endif
		    } else {
			/* create new tcpstate */
			tcpstate = tcpstate_new(from, to, sport, dport);
		    }
		    tcpstate->last_use = ts.tv_sec;
		    tcpstate->start = seq + 1; /* add 1 for the SYN */
		    tcpstate->maxdiff = 1;
		    tcpstate->dnslen = 0;
		    return;
		}
		if (tcpstate) {
		    uint32_t seqdiff = seq - tcpstate->start;
		    if (dumptrace >= 3)
			fprintf(stderr, "diff=%08x; ", seqdiff);
		    if (seqdiff == 0 && len > 2) {
			/* This is the first segment of the stream, and
			 * contains the dnslen and dns header, so we can
			 * filter on it. */
			if (dumptrace >= 3)
			    fprintf(stderr, "len+hdr\n");
			dnslen = tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
			dnspkt = pkt + 2;
			if (dnslen > len - 2)
			    dnslen = len - 2;
			flags |= DNSCAP_OUTPUT_ISDNS;
			tcpstate->maxdiff = (uint32_t)len;
		    } else if (seqdiff == 0 && len == 2) {
			/* This is the first segment of the stream, but only
			 * contains the dnslen. */
			if (dumptrace >= 3)
			    fprintf(stderr, "len\n");
			tcpstate->dnslen = (pkt[0] << 8) | (pkt[1] << 0);
			tcpstate->maxdiff = (uint32_t)len;
			output(descr, from, to, proto, flags, sport, dport, ts,
			    pkt_copy, olen, NULL, 0);
			return;
		    } else if ((seqdiff == 0 && len == 1) || seqdiff == 1) {
			/* shouldn't happen */
			discard(tcpstate, NULL);
			return;
		    } else if (seqdiff == 2) {
			/* This is not the first segment, but it does contain
			 * the first dns header, so we can filter on it. */
			if (dumptrace >= 3)
			    fprintf(stderr, "hdr\n");
			tcpstate->maxdiff = seqdiff + (uint32_t)len;
			dnslen = tcpstate->dnslen;
			dnspkt = pkt;
			if (dnslen == 0) /* we never received it */
			    dnslen = len;
			if (dnslen > len)
			    dnslen = len;
			flags |= DNSCAP_OUTPUT_ISDNS;
		    } else if (seqdiff > tcpstate->maxdiff + MAX_TCP_WINDOW) {
			/* This segment is outside the window. */
			if (dumptrace >= 3)
			    fprintf(stderr, "out of window\n");
			return;
		    } else if (len == 0) {
			/* No payload (e.g., an ACK) */
			if (dumptrace >= 3)
			    fprintf(stderr, "empty\n");
			return;
		    } else {
			/* non-first */
			if (dumptrace >= 3)
			    fprintf(stderr, "keep\n");
			if (tcpstate->maxdiff < seqdiff + (uint32_t)len)
			    tcpstate->maxdiff = seqdiff + (uint32_t)len;
			output(descr, from, to, proto, flags, sport, dport, ts,
			    pkt_copy, olen, NULL, 0);
			return;
		    }
		} else {
		    if (dumptrace >= 3)
			fprintf(stderr, "no state\n");
		    /* There is no state for this stream.  Either we never saw
		     * a SYN for this stream, or we have already decided to
		     * discard this stream. */
		    return;
		}
#endif
		break;
	}
	default:
		return;
	}

	/* Application. */
	if (dnslen < sizeof dns) {
		discard(tcpstate, "too small");
		return;
	}
	memcpy(&dns, dnspkt, sizeof dns);

	/* Policy filtering. */
	if (dns.qr == 0 && dport == dns_port) {
		if ((dir_wanted & DIR_INITIATE) == 0) {
			discard(tcpstate, "unwanted dir=i");
			return;
		}
		initiator = from;
		responder = to;
		response = FALSE;
	} else if (dns.qr != 0 && sport == dns_port) {
		if ((dir_wanted & DIR_RESPONSE) == 0) {
			discard(tcpstate, "unwanted dir=r");
			return;
		}
		initiator = to;
		responder = from;
		response = TRUE;
	} else {
		discard(tcpstate, "unwanted direction/port");
		return;
	}
	if ((!EMPTY(initiators) &&
	     !ep_present(&initiators, initiator)) ||
	    (!EMPTY(responders) &&
	     !ep_present(&responders, responder)))
	{
		discard(tcpstate, "unwanted host");
		return;
	}
	if ((!EMPTY(not_initiators) &&
	     ep_present(&not_initiators, initiator)) ||
	    (!EMPTY(not_responders) &&
	     ep_present(&not_responders, responder)))
	{
		discard(tcpstate, "missing required host");
		return;
	}
	if (!(((msg_wanted & MSG_QUERY) != 0 && dns.opcode == ns_o_query) ||
	      ((msg_wanted & MSG_UPDATE) != 0 && dns.opcode == ns_o_update) ||
	      ((msg_wanted & MSG_NOTIFY) != 0 && dns.opcode == ns_o_notify)))
	{
		discard(tcpstate, "unwanted opcode");
		return;
	}
	if (response) {
		int match_tc = (dns.tc != 0 && err_wanted & ERR_TRUNC);
		int match_rcode = err_wanted & (ERR_RCODE_BASE << dns.rcode);

		if (!match_tc && !match_rcode) {
			discard(tcpstate, "unwanted error code");
			return;
		}
		if (!EMPTY(drop_responders) && ep_present(&drop_responders, responder)) {
			discard(tcpstate, "dropped response due to -Y");
			return;
		}
	}
#if HAVE_NS_INITPARSE && HAVE_NS_PARSERR && HAVE_NS_SPRINTRR
	if (!EMPTY(myregexes)) {
		int match, negmatch;
		ns_msg msg;
		ns_sect s;

		match = FALSE;
		negmatch = FALSE;
		if (ns_initparse(dnspkt, dnslen, &msg) < 0) {
			discard(tcpstate, "failed parse");
			return;
		}
		for (s = ns_s_qd; s < ns_s_max && !match; s++) {
			char pres[SNAPLEN*4];
			const char *look;
			int count, n;
			ns_rr rr;

			count = ns_msg_count(msg, s);
			for (n = 0; n < count && !negmatch; n++) {
				myregex_ptr myregex;

				if (ns_parserr(&msg, s, n, &rr) < 0) {
					discard(tcpstate, "failed parse");
					return;
				}
				if (s == ns_s_qd) {
					look = ns_rr_name(rr);
				} else {
					if (ns_sprintrr(&msg, &rr, NULL, ".",
							pres, sizeof pres) < 0)
					{
						discard(tcpstate, "failed parse");
						return;
					}
					look = pres;
				}
				for (myregex = HEAD(myregexes);
				     myregex != NULL && !negmatch;
				     myregex = NEXT(myregex, link)) {
					if (((!match) || myregex->not) &&
					    regexec(&myregex->reg, look,
						    0, NULL, 0) == 0)
					{
						if (myregex->not) {
							negmatch = TRUE;
							match = FALSE;
						} else
							match = TRUE;
						if (dumptrace >= 2)
							fprintf(stderr,
						   "; \"%s\" ~ /%s/ %d %d\n",
								look,
								myregex->str,
								match,
								negmatch);
					}
				}
			}
		}
		if (!match) {
			discard(tcpstate, "failed regex match");
			return;
		}
	}
#endif /* HAVE_NS_INITPARSE && HAVE_NS_PARSERR && HAVE_NS_SPRINTRR */

	/* Policy hiding. */
	if (end_hide != 0) {
		switch (from.af) {
		case AF_INET: {
			struct in_addr *init_addr, *resp_addr;
			uint16_t *init_port;

			if (dns.qr == 0) {
			    init_addr = &ip->ip_src;
			    resp_addr = &ip->ip_dst;
			    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
			} else {
			    init_addr = &ip->ip_dst;
			    resp_addr = &ip->ip_src;
			    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
				init_addr->s_addr = HIDE_INET;
				*init_port = htons(HIDE_PORT);
			}
			if ((end_hide & END_RESPONDER) != 0)
				resp_addr->s_addr = HIDE_INET;
			ip->ip_sum = ~in_checksum((u_char *)ip, sizeof *ip);
			if (udp) udp->uh_sum = 0U;
			break;
		    }
		case AF_INET6: {
			struct in6_addr *init_addr, *resp_addr;
			uint16_t *init_port;

			if (dns.qr == 0) {
			    init_addr = &ipv6->ip6_src;
			    resp_addr = &ipv6->ip6_dst;
			    init_port = tcp ? &tcp->th_sport : &udp->uh_sport;
			} else {
			    init_addr = &ipv6->ip6_dst;
			    resp_addr = &ipv6->ip6_src;
			    init_port = tcp ? &tcp->th_dport : &udp->uh_dport;
			}
			if ((end_hide & END_INITIATOR) != 0) {
                memcpy(init_addr, HIDE_INET6, sizeof(struct in6_addr));
				*init_port = htons(HIDE_PORT);
			}
			if ((end_hide & END_RESPONDER) != 0)
                memcpy(resp_addr, HIDE_INET6, sizeof(struct in6_addr));
			if (udp) udp->uh_sum = 0U;
			break;
		    }
		default:
			abort();
		}
	}
	output(descr, from, to, proto, flags, sport, dport, ts,
	    pkt_copy, olen, dnspkt, dnslen);
}

/*
 * when flags & DNSCAP_OUTPUT_ISDNS, payload points to a DNS packet
 */
static void
output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, const unsigned olen,
    const u_char *payload, const unsigned payloadlen)
{
	struct plugin *p;

	msgcount++;
	capturedbytes += olen;

	if (dumptrace >= 3) {
		fprintf(stderr, "output: capturedbytes=%zu, proto=%d, isfrag=%s, isdns=%s, olen=%u, payloadlen=%u\n",
			capturedbytes,
			proto,
			flags & DNSCAP_OUTPUT_ISFRAG ? "yes" : "no",
			flags & DNSCAP_OUTPUT_ISDNS ? "yes" : "no",
			olen,
			payloadlen
		);
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
		    h.ts = ts;
		    h.len = h.caplen = olen;
		    pcap_dump((u_char *)dumper, &h, pkt_copy);
		    if (flush)
			    pcap_dump_flush(dumper);
        }
        else if (options.dump_format == cbor && (flags & DNSCAP_OUTPUT_ISDNS) && payload) {
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
            }
            else if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
            }
        }
        else if (options.dump_format == cds) {
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
            }
            else if (ret != DUMP_CDS_OK) {
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

static int
dumper_open(my_bpftimeval ts) {
	const char *t = NULL;
	struct plugin *p;

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
		char sbuf[64];

		strftime(sbuf, 64, "%Y%m%d.%H%M%S", gmtime((time_t *) &ts.tv_sec));
		if (asprintf(&dumpname, "%s.%s.%06lu%s",
			     dump_base, sbuf,
			     (u_long) ts.tv_usec, dump_suffix ? dump_suffix : "") < 0 ||
		    asprintf(&dumpnamepart, "%s.part", dumpname) < 0)
		{
			logerr("asprintf: %s", strerror(errno));
			return (TRUE);
		}
		t = dumpnamepart;
	}
	if (NULL != t) {
	    if (options.dump_format == pcap) {
		    dumper = pcap_dump_open(pcap_dead, t);
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
		u_int seconds;
		time_t targ;

		gettimeofday(&now, NULL);
		while (now.tv_usec >= MILLION) {
			now.tv_sec++;
			now.tv_usec -= MILLION;
		}
		targ = (((now.tv_sec + (limit_seconds / 2))
			 / limit_seconds) + 1) * limit_seconds;
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

void stat_callback(u_char* user, const struct pcap_stat* stats, const char* name, int dlt) {
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
			mypcap->drops
		);
    }
}

static void
do_pcap_stats()
{
    logerr("total drops: %lu", pcap_drops);
    pcap_thread_stats(&pcap_thread, stat_callback, 0);
}

static int
dumper_close(my_bpftimeval ts) {
	int ret = FALSE;
	struct plugin *p;

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
	}
	else if (options.dump_format == cbor) {
	    int ret;

    	if (dump_type == to_stdout) {
    	    ret = dump_cbor(stdout);

    	    if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
    	    }
    	}
    	else if (dump_type == to_file) {
    	    FILE * fp;

    	    if (!(fp = fopen(dumpnamepart, "w"))) {
                fprintf(stderr, "%s: fopen(%s) failed: %s\n", ProgramName, dumpnamepart, strerror(errno));
                exit(1);
    	    }
    	    ret = dump_cbor(fp);
    	    if (ret != DUMP_CBOR_OK) {
                fprintf(stderr, "%s: output to cbor failed [%u]\n", ProgramName, ret);
                exit(1);
    	    }
    	    fclose(fp);
    	}
	}
	else if (options.dump_format == cds) {
	    int ret;

    	if (dump_type == to_stdout) {
    	    ret = dump_cds(stdout);

    	    if (ret != DUMP_CDS_OK) {
                fprintf(stderr, "%s: output to cds failed [%u]\n", ProgramName, ret);
                exit(1);
    	    }
    	}
    	else if (dump_type == to_file) {
    	    FILE * fp;

    	    if (!(fp = fopen(dumpnamepart, "w"))) {
                fprintf(stderr, "%s: fopen(%s) failed: %s\n", ProgramName, dumpnamepart, strerror(errno));
                exit(1);
    	    }
    	    ret = dump_cds(fp);
    	    if (ret != DUMP_CDS_OK) {
                fprintf(stderr, "%s: output to cds failed [%u]\n", ProgramName, ret);
                exit(1);
    	    }
    	    fclose(fp);
    	}
	}

	if (dump_type == to_stdout) {
		assert(dumpname == NULL);
		assert(dumpnamepart == NULL);
		if (dumptrace >= 1)
			fprintf(stderr, "%s: breaking\n", ProgramName);
		ret = TRUE;
	} else if (dump_type == to_file) {
		char *cmd = NULL;;

		if (dumptrace >= 1)
			fprintf(stderr, "%s: closing %s\n",
				ProgramName, dumpname);
		if (rename(dumpnamepart, dumpname)) {
		    logerr("rename: %s", strerror(errno));
		    return ret;
		}
		if (kick_cmd != NULL)
			if (asprintf(&cmd, "%s %s &", kick_cmd, dumpname) < 0){
				logerr("asprintf: %s", strerror(errno));
				cmd = NULL;
			}
		free(dumpnamepart); dumpnamepart = NULL;
		free(dumpname); dumpname = NULL;
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

static void
sigclose(int signum) {
	if (0 == last_ts.tv_sec)
		gettimeofday(&last_ts, NULL);
	if (signum == SIGALRM)
		alarm_set = FALSE;
	if (dumper_close(last_ts))
		breakloop_pcaps();
}

static void
sigbreak(int signum __attribute__((unused))) {
	logerr("%s: signalled break", ProgramName);
	main_exit = TRUE;
	breakloop_pcaps();
}

#if HAVE_PTHREAD
static void *
sigthread(void * arg) {
    sigset_t *set = (sigset_t*)arg;
    int sig, err;

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

    return 0;
}
#endif

static uint16_t
in_checksum(const u_char *ptr, size_t len) {
	unsigned sum = 0, top;

	/* Main body. */
	while (len >= NS_INT16SZ) {
		sum += *(const uint16_t *)ptr;
		ptr += NS_INT16SZ;
		len -= NS_INT16SZ;
	}

	/* Leftover octet? */
	if (len != 0)
		sum += *ptr;

	/* Leftover carries? */
	while ((top = (sum >> 16)) != 0)
		sum = ((uint16_t)sum) + top;

	/* Caller should ~ this result. */
	return ((uint16_t) sum);
}

static int
logerr(const char *fmt, ...)
{
  va_list ap;
  int x = 1;
  va_start(ap, fmt);
  if (background)
    vsyslog(LOG_NOTICE, fmt, ap);
  else {
    x = vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
  }
  va_end(ap);
  return x;
}

static void
daemonize(void)
{
  pid_t pid;
#ifdef TIOCNOTTY
  int i;
#endif
  if ((pid = fork()) < 0) {
    logerr("fork failed: %s", strerror(errno));
    exit(1);
  }
  else if (pid > 0)
    exit(0);
  openlog("dnscap", 0, LOG_DAEMON);
  if (setsid() < 0) {
    logerr("setsid failed: %s", strerror(errno));
    exit(1);
  }
#ifdef TIOCNOTTY
  if ((i = open("/dev/tty", O_RDWR)) >= 0) {
    ioctl(i, TIOCNOTTY, NULL);
    close(i);
  }
#endif
  logerr("Backgrounded as pid %u", getpid());
}
