# Copyright (c) 2016-2018, OARC, Inc.
# Copyright (c) 2007, The Measurement Factory, Inc.
# Copyright (c) 2007, Internet Systems Consortium, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

AC_PREREQ(2.61)
AC_INIT([dnscap], [1.9.0], [dnscap-users@dns-oarc.net], [dnscap], [https://github.com/DNS-OARC/dnscap/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/dnscap.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])

# pcap_thread
AC_ARG_ENABLE(threads,
    [AS_HELP_STRING([--enable-threads],
        [enable the usage of threads (default disabled)])],
    [AX_PCAP_THREAD],
    [AX_PCAP_THREAD_PCAP])

# Checks for libraries.
AC_CHECK_LIB([bind], [ns_initparse], [], [AC_CHECK_LIB([bind], [__ns_initparse])])
AC_CHECK_LIB([resolv], [res_mkquery], [], [
	AC_CHECK_LIB([resolv], [__res_mkquery], [], [
		AC_CHECK_LIB([resolv], [res_9_mkquery])
	])
])
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([tinycbor], [cbor_parser_init])
AM_CONDITIONAL([HAVE_CBOR], [test "x$ac_cv_lib_tinycbor_cbor_parser_init" = "xyes"])
AC_CHECK_LIB([ldns], [ldns_wire2pkt])
AM_CONDITIONAL([HAVE_LDNS], [test "x$ac_cv_lib_ldns_ldns_wire2pkt" = "xyes"])
AC_CHECK_LIB([z], [gzopen])

# Check for OS specific libraries
case "$host_os" in
    # HPUX
    hpux*)
        AC_CHECK_LIB([hplx], [main])
        ;;

    # Solaris
    solaris*)
        AC_CHECK_LIB([rt], [main])
        AC_CHECK_LIB([md5], [main])
        AC_CHECK_LIB([socket], [main])
        AC_CHECK_LIB([nsl], [main])
        ;;
esac

# Checks for header files.
AC_HEADER_RESOLV
AC_HEADER_TIME
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h])
AC_CHECK_HEADERS([sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([ldns/ldns.h arpa/nameser_compat.h cbor.h cbor/cbor.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([zlib.h])

# Checks for library functions.
AC_CHECK_FUNCS([snprintf])
AC_CHECK_FUNCS([setreuid setresuid setregid setresgid setegid seteuid])
AC_CHECK_FUNCS([funopen fopencookie gzopen])
AC_CHECK_FUNC([ns_initparse],
    [AC_DEFINE([HAVE_NS_INITPARSE], [1], [Define to 1 if you have the `ns_initparse' function.])],
    [AC_CHECK_FUNC(__ns_initparse,
        [AC_DEFINE([HAVE_NS_INITPARSE], [1], [Define to 1 if you have the `ns_initparse' function.])]
    )]
)
AC_CHECK_FUNC([ns_parserr],
    [AC_DEFINE([HAVE_NS_PARSERR], [1], [Define to 1 if you have the `ns_parserr' function.])],
    [AC_CHECK_FUNC(__ns_parserr,
        [AC_DEFINE([HAVE_NS_PARSERR], [1], [Define to 1 if you have the `ns_parserr' function.])]
    )]
)
AC_CHECK_FUNC([ns_sprintrr],
    [AC_DEFINE([HAVE_NS_SPRINTRR], [1], [Define to 1 if you have the `ns_sprintrr' function.])],
    [AC_CHECK_FUNC(__ns_sprintrr,
        [AC_DEFINE([HAVE_NS_SPRINTRR], [1], [Define to 1 if you have the `ns_sprintrr' function.])]
    )]
)
AC_CHECK_FUNC([ns_name_uncompress],
    [AC_DEFINE([HAVE_NS_NAME_UNCOMPRESS], [1], [Define to 1 if you have the `ns_name_uncompress' function.])],
    [AC_CHECK_FUNC(__ns_name_uncompress,
        [AC_DEFINE([HAVE_NS_NAME_UNCOMPRESS], [1], [Define to 1 if you have the `ns_name_uncompress' function.])]
    )]
)
AC_CHECK_FUNC([p_rcode],
    [AC_DEFINE([HAVE_P_RCODE], [1], [Define to 1 if you have the `p_rcode' function.])],
    [AC_CHECK_FUNC(__p_rcode,
        [AC_DEFINE([HAVE_P_RCODE], [1], [Define to 1 if you have the `p_rcode' function.])]
    )]
)
AC_CHECK_FUNCS([__assertion_failed])

# Check for SECCOMP
SECCOMPFLAGS=
AC_ARG_ENABLE(seccomp, AC_HELP_STRING([--enable-seccomp], [Linux seccomp-bpf sandbox]))
case "$enable_seccomp" in
    yes)
        AC_DEFINE_UNQUOTED([USE_SECCOMP], [1], [Define this to enable Linux seccomp-bpf sandbox.])
        SECCOMPFLAGS="-lseccomp -fPIE -fstack-protector-all -Wl,-z,relro -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2"
        ;;

    *)
        ;;
esac
AC_SUBST(SECCOMPFLAGS, ["$SECCOMPFLAGS"])

# Output Makefiles
AC_CONFIG_FILES([
    Makefile
    src/Makefile
	src/test/Makefile
    plugins/Makefile
    plugins/pcapdump/Makefile
    plugins/rssm/Makefile
    plugins/txtout/Makefile
    plugins/rzkeychange/Makefile
    plugins/royparse/Makefile
])
AC_OUTPUT
