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

#include "daemon.h"
#include "log.h"

void drop_privileges(void)
{
    struct rlimit  rss;
    struct passwd  pwd;
    struct passwd* result;
    size_t         pwdBufSize;
    char*          pwdBuf;
    unsigned int   s;
    uid_t          oldUID = getuid();
    uid_t          oldGID = getgid();
    uid_t          dropUID;
    gid_t          dropGID;
    const char*    user;
    struct group*  grp = 0;

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
            } else {
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
        } else {
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
    if (mem_limit_set) {
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
    if (use_seccomp == FALSE) {
        return;
    }

#if 0
    /*
     * Setting SCMP_ACT_TRAP means the process will get
     * a SIGSYS signal when a bad syscall is executed
     * This is for debugging and should be monitored.
     */

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
#endif

    /*
     * SCMP_ACT_KILL tells the kernel to kill the process
     * when a syscall we did not filter on is called.
     * This should be uncommented in production.
     */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    if (ctx == NULL) {
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

    if (r != 0) {
        fprintf(stderr, "Unable to apply seccomp-bpf filter\n");
        seccomp_release(ctx);
        exit(1);
    }

    r = seccomp_load(ctx);

    if (r < 0) {
        seccomp_release(ctx);
        fprintf(stderr, "Unable to load seccomp-bpf filter\n");
        exit(1);
    }
#endif
}

void daemonize(void)
{
    pid_t pid;
#ifdef TIOCNOTTY
    int i;
#endif
    if ((pid = fork()) < 0) {
        logerr("fork failed: %s", strerror(errno));
        exit(1);
    } else if (pid > 0)
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
