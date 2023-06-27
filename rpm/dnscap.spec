Name:           dnscap
Version:        2.1.3
Release:        1%{?dist}
Summary:        Network capture utility designed specifically for DNS traffic
Group:          Productivity/Networking/DNS/Utilities

License:        BSD-3-Clause
URL:            https://www.dns-oarc.net/tools/dnscap
# Source needs to be generated by dist-tools/create-source-packages, see
# https://github.com/jelu/dist-tools
Source0:        https://www.dns-oarc.net/files/dnscap/%{name}-%{version}.tar.gz?/%{name}_%{version}.orig.tar.gz

BuildRequires:  libpcap-devel
BuildRequires:  ldns-devel
BuildRequires:  openssl-devel
BuildRequires:  zlib-devel
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  perl-YAML
BuildRequires:  cryptopant-devel
BuildRequires:  pkgconfig

%description
dnscap is a network capture utility designed specifically for DNS
traffic. It produces binary data in pcap(3) format. This utility
is similar to tcpdump(1), but has a number of features tailored
to DNS transactions and protocol options.


%prep
%setup -q -n %{name}_%{version}


%build
sh autogen.sh
%configure
make %{?_smp_mflags}


%check
make test


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
%{_bindir}/*
%{_datadir}/doc/*
%{_mandir}/man1/*
%{_libdir}/*


%changelog
* Tue Jun 27 2023 Jerry Lundström <lundstrom.jerry@gmail.com> 2.1.3-1
- Release 2.1.3
  * This release fixes a memory leak when using pattern matching options
    `-x` or `-X`, the LDNS packet was not freed correctly.
  * The processing of the LDNS packet during matching has also been
    improved.
  * Commits:
    3990795 Test
    ee5d554 Pattern match
* Thu Jun 15 2023 Jerry Lundström <lundstrom.jerry@gmail.com> 2.1.2-1
- Release 2.1.2
  * This release fixes reusing of TCP state during an out-of-memory event,
    the reused structure was not cleared of old information. And fixes
    compatibility with OpenSSL v3.0+ due to deprecated functions.
  * Commits:
    756f78a OpenSSL 3.0+
    d2bd12f tcpstate on out of memory
* Fri Feb 03 2023 Jerry Lundström <lundstrom.jerry@gmail.com> 2.1.1-1
- Release 2.1.1
  * This release includes fixes to TCP state code, anonymizing plugins and
    handling of EDNS extended error code.
    - Ken Renards @kdrenard (PR #275) fixed handling of EDNS extended error
      code, the previous code looked at `arcount` but ldns "consumes" OPT
      records so the count could be zero even with existing extended error
      code.
    - Changed anonymizing plugins to anonymize both sending and receiving
      IP address if both used the server port, part of issue #276 reported
      by Duane Wessels @wessels. This fixes situations where clients
      weren't anonymize because they sent using that port.
    - Fixed multiple issues with garbage collection in TCP state handling.
      It was reusing a pointer that was meant to return the current TCP
      state so it could return the wrong state when garbage collection
      was triggered.
      It also just unlinked stale states and didn't free them, new code
      uses the discard function so released state is also tagged as
      "gc stale".
      Lastly the discard function was fixed to clear the current TCP state
      pointer used by plugins if the discarded state was it.
  * Commits:
    7f2ddcf Copyright
    fd5b744 CodeQL alerts
    726d241 TCP state GC
    dff421e Anonymize clients
    2eb8489 Add CodeQL workflow for GitHub code scanning
    c5a0919 Better test for presence of EDNS option with extended error code
* Fri Sep 09 2022 Jerry Lundström <lundstrom.jerry@gmail.com> 2.1.0-1
- Release 2.1.0
  * This release adds a new option (`-o pid_file=<file>`) to specify a PID
    file when running as daemon, corrects handling of LDNS include files
    for some plugins and updates the Root Server Scaling Measurement (RSSM)
    plugin w.r.t. the upcoming version 5 of RSSAC002 specifications.
  * The RSSM plugin can now optionally generate `label-count` metric. This
    is enabled with `-L` and is tagged as `rssac002v5-draft` until v5 is
    finalized.
    The merge tool `dnscap-rssm-rssac002` has also been updated because of
    this, there is now `--skip-unsupported` to skip all unsupported
    RSSAC002 version metrics instead of `die()`'ing.
  * Commits:
    ca7707d RSSAC002v5 label-count metric
    3ebee80 Made label count metric optional
    41b029a Adding support for label acount metric
    799c3fe Missing includes
    7089f12 PID file
* Mon Jun 13 2022 Jerry Lundström <lundstrom.jerry@gmail.com> 2.0.3-1
- Release 2.0.3
  * Thanks to a patch from Duane Wessels (@wessels) this release fixes
    an issue with filtering where DNS messages without a question section
    would bypass it.
  * Commits:
    ba2112c Fix COPR
    0e019ab Filtering
    c7e1c8f Refactor and fix qtype and qname matching/filtering.
* Tue Mar 08 2022 Jerry Lundström <lundstrom.jerry@gmail.com> 2.0.2-1
- Release 2.0.2
  * Thanks to a patch from Duane Wessels (@wessels) this release fixes
    memory leaks when using `-x`/`-X` regexp filtering due to incorrect
    usage of LDNS library.
  * Other minor changes:
    - Clarify what happens if you don't specify `-i` and add information about `any` and `all`
    - Update debhelper compatibility level to 10
  * Commits:
    a8925a7 ldns_pkt_all() clones RRs which need to be freed with ldns_rr_list_deep_free()
    5104814 Doc
    30c36aa debhelper
    4ae4356 Bye Travis
* Thu Mar 11 2021 Jerry Lundström <lundstrom.jerry@gmail.com> 2.0.1-1
- Release 2.0.1
  * Fixed incorrect line break in eventlog's (plugin) output.
  * Commits:
    5df363c remove trailing newline
* Fri Feb 12 2021 Jerry Lundström <lundstrom.jerry@gmail.com> 2.0.0-1
- Release 2.0.0
  * This major release contains three backward incompatible changes, two
    new command line options and a completely restructured man-page(!),
    please read the change notes carefully before upgrading!
  * The first backward incompatible change has to do with the removal of
    libbind dependency. This library was causing segfaults on OpenBSD due to
    shared (and overwritten) symbols with OpenBSD's libc.
    It was replaced with LDNS and LDNS renders domain names as Fully
    Qualified Domain Names (FQDN, the trailing dot!) so every output of a
    domain name has been changed to a FQDN.
    This also changes `-X`/`-x`, which will now match against FQDNs.
  * The second backward incompatible change is that `-6` has been removed.
    This was used to alter the BPF in order to "fix" it, dnscap adds
    specific filters to IP and UDP headers which does not work for IPv6
    traffic.
    The generated BPF has been changed to allow IPv6 to always pass, making
    the option obsolete. IPv6 filtering is then done in dnscap.
  * The last backward incompatible change has to do with the output format
    of `-g` related to EDNS0 and is now more consistent with the rest of
    the parsable output:
    - No more spaces in the output
    - Fix incorrect `\` and extra empty new-line
    - All EDNS0 options are added after `edns0[...]` using comma separation, example: `edns0[],edns0opt[],...`
    - Client Subnet format: `edns0opt[ECS,family=nn,source=nn,scope=nn,addr=...]`
    - Unknown/unsupported code: `edns0opt[code=nn,codelen=nn]`
    - Parsing error messages have changed, they came from libbind, now comes from LDNS
  * New options:
    - Add `-q` and `-Q` to filter on matched/not matched QTYPE
  * Bugfixes:
    - Fix memory leak in EDNS0 ECS address parsing
    - `network`: Fix sonarcloud issues, potential `memcpy()` of null pointer
  * Other changes:
    - Fix CBOR output inclusion, LDNS is always available now
    - Add macros for Apple and Windows endian functions
    - Restructure and correct the man-page
  * Commits:
    557e5f5 man-page
    025529f v6bug, interval
    37b79e9 FQDN
    ebcf434 QTYPE match, args, tests
    0cb5562 v6bug
    75f6115 Endian
    aaeb213 Sonarcloud
    8685946 CBOR output
    3e26802 Sonarcloud
    30aa366 libbind
    3f94d0b Mattermost
* Thu Oct 22 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.12.0-1
- Release 1.12.0
  * This release fixes the handling of `-?` option for dnscap and all plugins,
    previously the handling varied between places and depending on `getopt()`
    implementation an invalid option could return the wrong exit code.
  * Other changes:
    - Fix typo in configure help text
    - `plugins/anonmask`: Fix typo in help text
    - `plugins/rzkeychange`:
      - Add `-D`, dry run mode, for testing
      - Fix handling of `-a` and error on too many
  * KNOWN ISSUES:
    On OpenBSD the system library libc exports the same symbols as libbind
    does and this causes runtime warnings. Until now this has not caused any
    known problems but is now also causing segfaults if the packet filter used
    (BPF) includes IPv6 addresses.
    On all other platforms OARC supports, these symbols are macros and in so
    should not cause any problem.
  * Commits:
    ee478c0 Known issues
    2f9d957 Tests
    3c663a2 Tests
    c88efc5 rzkeychange test
    f062f33 Tests
* Thu Aug 20 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.11.1-1
- Release 1.11.1
  * This release fixes a lot of issues found by code analysis, adds a
    explicit memory zeroing function to remove account information (read
    when dropping privileges) and adds code coverage reporting.
  * The `dnscap_memzero()` will use `explicit_bzero()` on FreeBSD and
    OpenBSD, or `memset_s()` (if supported), otherwise it will manually
    set the memory to zero. This will hopefully ensure that the memory
    is zeroed as compilers can optimize out `memset()`'s that is just
    before `free()`.
  * The plugins exit code for the help option `-?` has been changed to 0
    to have the same as `dnscap -?`.
  * Commits:
    d9747ee memzero
    1cf17c6 Coverage
    19c7120 Coverage
    7435676 Sonarcloud
    928e181 Sonarcloud
    ca4afd0 Sonarcloud
    028f5e0 Badges
    db0d6a1 LGTM
* Mon Jun 01 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.11.0-1
- Release 1.11.0
  * This release includes a new plugin called `eventlog`, contributed
    by Byron Darrah (@ByronDarrah), output DNS activity as log events,
    including answers to A and AAAA queries.
  * Other changes includes compile warning and code analysis fixes.
  * Commits:
    382eac4 COPR
    4c03650 Compile warn
    21d6a67 Slight change -- wording now matches usage() output.
    dd19b0b Added the eventlog.so plugin...
    1ebf504 Added new dnscap plugin: evenlog.so...
    f3f9aaa Compile warnings
* Mon Mar 02 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.10.4-1
- Release 1.10.4
  * Fixed a bug that would not drop privileges when not specifying any
    interface (which is equal to capturing on all interfaces).
  * Added functionality to set the supplemental groups when dropping
    privileges and changing user, or clear them if that is not supported.
  * Other changes includes corrected man-page about '-w' and update to
    documentation.
  * Commits:
    a0285e4 drop privileges errors, initgroups/setgroups
    96336f3 daemon: Attempt to drop supplemental groups
    467a9a7 Drop privileges
    de940a8 man-page -w
    187ec43 README
* Wed Oct 02 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 1.10.3-1
- Release 1.10.3
  * Fixed plugins inclusion in deb packages for Debian and Ubuntu.
  * Commits:
    017ebb2 Deb packages
    cf59143 COPR, spec
* Mon Aug 05 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 1.10.2-1
- Release 1.10.2
  * Fixed bug in the handling of defragmentation configuration which lead
    to the use of a local scope variable later on and caused unexpected
    behavior.
  * Commits:
    91692b8 Frag conf
    6a74376 Package
    d0d1a6d Package
* Mon Jul 08 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 1.10.1-1
- Release 1.10.1
  * Fix various issues found by code analysis tools, a few compiler warnings
    removed, undefined bit shift behavior fixed, parameter memory leaks
    plugged and documentation updates.
  * Fixes:
    - `dump_dns`: Remove usage of `strcpy()` and use `snprintf()` instead
      of `sprintf()`
    - `bpft`:
      - Use `text_ptr->len` to store length of generated text
      - Use `memcpy()` instead of `strcat()`
      - Remove unneeded `realloc()` and `strcpy()`
    - `plugins/cryptopan`: Fix strict-aliasing warnings
    - `network`: Rework part of `dl_pkt()` to remove usage of `strcpy()`
      and use `snprintf()` instead of `sprintf()`
    - `plugins/anonaes128`: Use `a6` as dest when copying v4 addresses for
      readability and code analysis
    - `plugins/cryptopan`: Run first pass separate to eliminate a 32bit
      shift by 32 (undefined behavior)
    - `plugins/cryptopant`: Fix memory leak of `keyfile` if `-k` is
      specified more then once
  * Documentation:
    - Update `README.md` with correction to building from git and note
      about PCAP on OpenBSD
    - Fix #190: Update link to `libbind` source
  * Commits:
    074923c Funding
    5d2e84c libbind
    8ee9f2a Travis-CI
    6babd09 Fixes
    bb2d1c7 README, compile warnings
    0d9cd9c LGTM, Travis-CI
* Mon Dec 03 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 1.10.0-1
- Release 1.10.0
  * This release adds a new plugin type "filter" and 5 new plugins that can
    do anonymization, deanonymization and masking of the IP addresses.
  * New features:
    - Check plugins for `pluginname_type()` which returns `enum plugin_type`,
      if missing the plugin is counted as an "output" plugin
    - New plugin type "filter" which calls `pluginname_filter()` prior of
      outputting any data or calling of "output" plugins, if the new function
      returns non-zero then the packet is filtered out (dropped)
    - New extension `DNSCAP_EXT_SET_IADDR` that gives access to a function
      for setting the from and to IP addresses both in the extracted data
      and the wire
  * New plugins:
    - `anonaes128`: Anonymize IP addresses using AES128
    - `anonmask`: Pseudo-anonymize IP addresses by masking them
    - `cryptopan`: Anonymize IP addresses using an extension to Crypto-PAn
      (College of Computing, Georgia Tech) made by David Stott (Lucent)
    - `cryptopant`: Anonymize IP addresses using cryptopANT, a different
      implementation of Crypto-PAn made by the ANT project at USC/ISI
    - `ipcrypt`: Anonymize IP addresses using ipcrypt create by
      Jean-Philippe Aumasson
  * Bugfixes:
    - Fix changing `royparse` and `txtout` with other plugins (thanks to
      Duane Wessels and Paul Hoffman)
    - Free pointers to allocated strings in `text_free()` (thanks to Michał
      Kępień)
    - Fix IP checksum calculation
  * Other changes:
    - `-B` and `-E` can be used without `-w` (thanks to Duane Wessels)
    - Use `pcap_findalldevs()` instead of `pcap_lookupdev()` (thanks to
      Michał Kępień)
    - Document and add `-?` option to all plugins
    - Fix clang `scan-build` bugs and LGTM alerts
    - Use `gmtime_r()` instead of `gmtime()`
    - Update `pcap-thread` to v4.0.0
  * Commits:
    67d8e2c Fix
    fb0ed02 Plugin documentation
    a2c9a6c cryptopant
    39db1ca Deanonymize, IPv6 test
    afc7107 Crypto-PAn, cryptopANT
    f1912cc OpenSSL, anonaes128
    f2bab62 ipcrypt, anonmask
    158b1e7 anonmask help
    60ece58 anonmask
    8f1b138 Plugin types, filter plugin, set iaddr extension, anonymization
            by masking
    b7d7991 IP checksum
    641a23a Free pointers to allocated strings in text_free()
    4d313bf pcap_findalldevs()
    091e0ca Use pcap_findalldevs() instead of pcap_lookupdev()
    6a7b25e Clean up use of feature test macros on Linux
    cbba14c Configure, uninitialized
    f228c9c Code formatting
    3fd738c man-page
    770168a Test
    714e4f5 Fix -B <begin> so that it works when reading offline pcap files.
    8675bea Test
    911fec9 Implementing test9 as a test of -B and -E command line args.
    a7cc72d -B <begin> and -E <end> can work fine without -w <base>.
    04c4928 Made the same changes to txtout as were in 165a786
    165a786 Workaround for stdio mystery causing duplicate royparse output.
* Wed Feb 28 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 1.9.0-1
- Release 1.9.0
  * This release adds a new option to change how the Berkeley Packet Filter
    is generated to include the host restrictions for all selections,
    previously this restriction would only apply to specific parts.
  * Additional tweaks to the RSSM plugin has been made to conform to the
    RSSAC002v3 specification. One noticeable change is that the plugin now
    requires the DNS to be parsed before counted, any error in the parsing
    will result in the message being left out of the statistics.
  * Changes:
    - Fix spacing in BPF filter to look better
    - Fix #146: Add `bpf_hosts_apply_all`, apply any host restriction to all
    - `plugin/rssm`:
      - Remove quoting of `start-period` and correctly handle empty hashes
      - Issue #152, Issue #91: Parse DNS before processing RSSM counters
    - `plugin/rssm/dnscap-rssm-rssac002`: Use `YAML::Dump()` for output
  * Commits:
    47d892b Issue #152: RSSM YAML output
    d4f1466 Issue #152, Issue #91: Parse DNS before processing RSSM counters
    68fc1ff BPF, `bpf_hosts_apply_all`
* Wed Feb 07 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 1.8.0-1
- Release 1.8.0
  * This release updates the TCP stream code in order to be able to look
    at more then just the first query, for handling already ongoing TCP
    connections without having seen SYN/ACK and for reassembly of the TCP
    stream prior of parsing it for DNS with an additional layer of parsing
    (see `reassemble_tcp_bfbparsedns`).
  * Updates to the Root Server Scaling Measurement (RSSM) plugin have also
    been made to bring it up to date with RSSAC002v3 specification, be
    able to output the YAML format described and an additional script to
    merge YAML files if the interval is less then the RSSAC002v3 24 hour
    period. See "Updates to the RSSM plugin" below and
    `plugins/rssm/README.md`.
  * New extended options:
    - `parse_ongoing_tcp`: Start tracking TCP connections even if SYN/ACK
      has not been seen
    - `allow_reset_tcpstate`: Allow external reset of TCP state
    - `reassemble_tcp`: Use to enable TCP stream reassembly
    - `reassemble_tcp_faultreset`: Number of faults before reseting TCP
      state when reassembly is enabled
    - `reassemble_tcp_bfbparsedns`: Enable an experimental additional layer
      of reassemble that uses `libbind` to parse the payload before accepting
      it. If the DNS is invalid it will move 2 bytes within the payload and
      treat it as a new payload, taking the DNS length again and restart
      the process. Requires `libbind` and `reassemble_tcp`.
  * New extension functions for plugins:
    - `DNSCAP_EXT_TCPSTATE_GETCURR`: Function to get a pointer for the
      current TCP state
    - `DNSCAP_EXT_TCPSTATE_RESET`: Function to reset a TCP state
  * New features:
    - Parse additional DNS queries in TCP connections
    - `-g` and the `txtout` plugin will reset TCP state (if allowed) on
      failure to parse DNS
  * Bugfixes:
    - Fix `-g` output, separate error message with a space
    - Fix TCP packets wrongfully flagged as DNS when using layers.
    - Fix TCP debug output when using layers, `ia_str()` is not safe to call
      twice in the same `printf` because of local buffer.
    - Fix exported extension functions, need to be file local
  * New tests for:
    - Multiple DNS queries in one TCP connection
    - Query over TCP without SYN
    - Queries over TCP with first query missing length
    - Queries over TCP with middle payloads missing
    - Add test with TCP stream that missing multiple packets in the middle
  * Updates to the RSSM plugin (`plugins/rssm`):
    - Add info about saving counts and sources
    - Fix memory leak on `fopen()` errors
    - Update to RSSAC002v3 specification
    - New options:
      - `-D` to disable forking on close
      - `-Y`: Use RSSAC002v3 YAML format when writing counters, the file
        will contain multiple YAML documents, one for each RSSAC002v3 metric
        Used with; -S adds custom metric `dnscap-rssm-sources` and -A adds
        `dnscap-rssm-aggregated-sources`
      - `-n`: Set the service name to use in RSSAC002v3 YAML
      - `-S`: Write source IPs into counters file with the prefix `source`
      - `-A`: Write aggregated IPv6(/64) sources into counters file with
        the prefix `aggregated-source`
      - `-a`: Write aggregated IPv6(/64) sources to
        `<name>.<timesec>.<timeusec>`
    - Add `dnscap-rssm-rssac002` Perl script for merging RSSAC002v3 YAML files
    - Add README.md for the plugin man-page for `dnscap-rssm-rssac002`
    - Add test for YAML output and merging of YAML files
  * Commits:
    c7058c8 Use file local functions for all extensions
    66b352d RSSM RSSAC002v3 YAML Tool
    b09efc2 `plugins/rssm` RSSAC002v3
    709aba6 Fix #89: Add additional reassembly layers that parses the
            payload byte for byte for valid DNS
    04fa013 Fix CID 1463944 (again)
    b1cf623 RSSM saving data and forking
    fb23305 Fix CID 1463944
    0fca1a8 Issue #89: TCP stream reassemble
    bb6428c CID 1463814: Check `ns_initparse()` for errors
    a57066f Fix #88: TCP handling
* Wed Dec 27 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.7.1-1
- Release 1.7.1
  * The library used for parsing DNS (libbind) is unable to parse DNS
    messages when there is padding at the end (the UDP/TCP payload is larger
    then the DNS message). This has been fixed by trying to find the actual
    DNS message size, walking all labels and RR data, and then retry parsing.
  * Other changes and bug-fixes:
    - Fix size when there is a VLAN to match output of `use_layers` yes/no
    - Add test of VLAN matching
    - Fix `hashtbl.c` building in `rssm`
    - Add test with padded DNS message
  * Commits:
    49e5400 Fix #127: If `ns_initparse()` returns `EMSGSIZE`, try and get
            actual size and reparse
    99bda0b Fix #98: VLAN
* Tue Dec 19 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.7.0-1
- Release 1.7.0
  * This release adds IP fragmentation handling by using layers in pcap-thread
    which also adds a new flag to output and modules. `DNSCAP_OUTPUT_ISLAYER`
    indicates that `pkt_copy` is equal to `payload` since the layers of the
    traffic have already been parsed. IP fragments are reassembled with the
    `pcap_thread_ext_frag` extension that is included in pcap-thread.
  * New extended (`-o`) options:
    - `use_layers`: Use pcap-thread layers to handle the traffic
    - `defrag_ipv4`: Enabled IPv4 de-fragmentation
    - `defrag_ipv6`: Enabled IPv6 de-fragmentation
    - `max_ipv4_fragments`: Set maximum fragmented IPv4 packets to track
    - `max_ipv4_fragments_per_packet`: Set the maximum IPv4 fragments per
      tracked packet
    - `max_ipv6_fragments`: Set maximum fragmented IPv6 packets to track
    - `max_ipv6_fragments_per_packet`: Set the maximum IPv6 fragments per
      tracked packet
  * Currently `-w` does not work with `use_layers` and the plugins `pcapdump`
    and `royparse` will discard output with the flag `DNSCAP_OUTPUT_ISLAYER`
    because they need access to the original packet.
  * The `rzkeychange` plugin now encodes certain flag bits in the data that
    it reports for RFC8145 key tag signaling. The flags of interest are:
    `DO`, `CD`, and `RD`. These are encoded in an bit-mask as a hexadecimal
    value before the `_ta` component of the query name.
  * Other changes and bug-fixes:
    - Fix #115: document `-g` output, see `OUTPUT FORMATS` `diagnostic` in
      `dnscap(1)` man-page
    - Add test to match output from non-layers runs with those using layers
    - Add test with fragmented DNS queries
    - Fix #120: CBOR/CDS compiles again, update tinycbor to v0.4.2
    - Fix `ip->ip_len` byte order
    - Fix parsing of IP packets with padding or missing parts of payload
  * Commits:
    0347f74 Add AUTHORS section in man-page
    ef1b68c Fix CID 1463073
    8a79f89 Layers
    a404d08 Update pcap-thread to v3.1.0, add test for padding fixes
    08402f1 Fix byte order bug.  ip->ip_len must be evaluated with ntohs().
    d6d2340 CBOR/CDS and formatting
    85ec2d8 Fix #87: IP fragmentation reassembly
    22bfd4a Documentation
    c35f19f Adding flag bits to rzkeychange RFC8145 key tag signaling data.
            This may be useful to find "false" key tag signals from sources
            that don't actually perform DNSSEC validation.
* Fri Dec 01 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.6.0-1
- Release 1.6.0
  * New additions to the plugins:
    - `rzkeychange` can now collect RFC8145 key tag signaling. Signals are
      saved during the collection interval, and then sent to the specified
      `-k <zone>`, one at a time, at the end of the interval. Only root zone
      signals are collected. Added by Duane Wessels (@wessels).
    - `royparse` is a new plugin to splits a PCAP into two streams, queries
      in PCAP format and responses in ASCII format. Created by Roy Arends
      (@RoyArends).
    - `txtout` new option `-s` for short output, only print QTYPE and QNAME
      for IN records. Added by Paul Hoffman (@paulehoffman)
    - The extension interface has been extended with `DNSCAP_EXT_IA_STR` to
      export the `ia_str()` function.
  * Bugfixes and other changes:
    - Remove duplicated hashtbl code
    - `rssm`: fix bug where count in table was taken out as `uint16_t` but
      was a `uint64_t`
    - Handle return values from hashtbl functions
    - `txtout`: removed unused `-f` options
    - Change `ia_str()` to use buffers with correct sizes, thanks to
      @RoyArends for spotting this!
  * Commits:
    3f78a31 Add copy/author text
    1bd914d Fix CID 1462343, 1462344, 1462345
    f9bb955 Fix `fprintf()` format for message size
    abedf84 Fix #105: `inet_ntop` buffers
    bfdcd0d Addresses the suggestions from Jerry.
    dda0996 royparse :)
    4f6520a royparse plugin finished
    f1aa4f2 Fix #103: Remove `opt_f`
    32355b7 Rearrange code to keep the change smaller and fix indentation
    d6612c1 Added -s to txtout for short output
    9d8d1ef Check return of `snprintf()`
    55f5aba Format code
    9f19ec3 Fixed memory leak in rzkeychange_keytagsignal()
    58b8784 Fix memory leaks and better return value checks in
            rzkeychange_submit_counts()
    b06659f Add server and node to keytag signal query name
    705a866 Always free response packets in rzkeychange plugin.
    e802843 Implement RFC8145 key tag signal collection in rzkeychange plugin
    5fbf6d0 Added extension for ia_str() so it can be used by rzkeychange
            plugin.
    3be8b8f Split `dnscap.c` into more files
    e431d14 Fix #92: hashtbl
* Mon Aug 21 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.5.1-1
- Release 1.5.1
  * Compatibility fixes for FreeBSD 11.1+ which is now packing `struct ip`
    and for OpenBSD.
  * Commits:
    17e3c92 FreeBSD is packing `struct ip`, need to `memcpy()`
    f8add66 Code formatting
    38cd585 Add documentation about libbind
    d1dd55b Fix #82: Update dependencies for OpenBSD
* Tue Jun 06 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.5.0-1
- Release 1.5.0
  * Added support for writing gzipped PCAP if the `-W` suffix ends with
    `.gz` and made `-X` work without `-x`. New inteface for plugins to
    tell them what extensions are available and a new plugin `rzkeychange`.
  * Plugin extensions:
    - Call `plugin_extension(ext, arg)` to tell plugin what extensions exists
    - Add extension for checking responder (`is_responder()`)
  * The rzkeychange plugin was developed by Duane Wessels 2016 in support
    of the root zone ZSK size increase. It is also being used in support of
    the 2017 root KSK rollover and collects the following measurements:
    - total number of responses sent
    - number of responses with TC bit set
    - number of responses over TCP
    - number of DNSKEY responses
    - number of ICMP_UNREACH_NEEDFRAG messages received
    - number of ICMP_TIMXCEED_INTRANS messages received
    - number of ICMP_TIMXCEED_REASS messages received
  * Other fixes (author Duane Wessels):
    - 232cbd0: Correct comment description for meaning of IPPROTO_AH
    - 181eaa4: Add #include <sys/time.h> for struct timeval on NetBSD
  * Commits:
    1d894e2 Make -x and -X work correctly together and update man-page
    34bc54c Make the -X option work without requiring a -x option.
    f43222e Fix CID 1440488, 1440489, 1440490
    aa54395 Update pcap-thread to v2.1.3
    81174ce Prepare SPEC for OSB/COPR
    21d7468 New plugin rzkeychange and plugin extensions
    38491a3 Config header is generated by autotools
    419a8ab Small tweaks and fixes for gzip support
    1967abc updated for earlier BSD versions
    f135c90 added auto gzip if the -W suffix ends with .gz
  * Commits during development of rzkeychange (author Duane Wessels):
    - 620828d: Add rzkeychange -z option to specify resolver IP addresses
    - 1f77987: Add -p and -t options to rzkeychange plugin to configure an
      alternate port and TCP. Useful for ssh tunnels.
    - 2a571f1: Split ICMP time exceeded counter into two counters for time
      exceeded due to TTL and another due to fragmentation
    - e4ee2d3: The rzkeychange data collection plugin uses
      `DNSCAP_EXT_IS_RESPONDER` extension to know if an IP address is a
      "responder" or not, because when dnscap is instructed to collect ICMP
      with -I, it processes all ICMP packets, not just those limited to
      responders (or initiators).
    - cee16b8: Add ICMP Time Exceeded to counters
    - ad8a227: Counting source IPs has performance impacts. #ifdef'd out for
      now add ICMP "frag needed" counts
    - c25e72b: Implemented DNS queries with ldns. First there will be some
      test queries to ensure the zone is reachable and configured to receive
      data. Then a query naming the fields, followed by the periodic queries
      delivering counts.
    - fd23be7: Make report zone, server, node command line argumements mandatory
    - 137789b: Adding rzkeychange plugin files
* Wed Mar 29 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.4.1-1
- Release 1.4.1
  * Fixed an issue that when compiled with libpcap that had a specific
    feature enabled it would result in a runtime error which could not be
    worked around.
  * Also fixed various compatibility issues and updated dependency
    documentation for CentOS.
  * Commits:
    785d4c4 Fix compiler warnings
    2d4df8d Fix #65: Update pcap-thread to v2.1.2
    26d3fbc Fix #64: Add missing dependency
    55e6741 Update pcap-thread to v2.1.1, fix issue with libpcap timestamp
            type
    c6fdb7a Fix typo and remove unused variables
* Mon Feb 27 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.4.0-1
- Release 1.4.0
  * Until it can be confirmed that the threaded code works as well as the
    non-threaded code it has been made optional and requires a configuration
    option to enable it during compilation.
  * New extended option:
    - `-o pcap_buffer_size=<bytes>` can be used to increase the capture
      buffer within pcap-thread/libpcap, this can help mitigate dropped
      packets by the kernel during breaks (like when closing dump file).
  * Commits:
    1c6fbb2 Update copyright year
    63ef665 Suppress OpenBSD warnings about symbols
    2c99946 pcap-thread v2.0.0, disable threads, errors handling
    4cade97 Fix #56: Update pcap-thread to v1.2.2 and add test
* Fri Dec 23 2016 Jerry Lundström <lundstrom.jerry@gmail.com> 1.3.0-1
- Release 1.3.0
  * Rare lockup has been fixed that could happen if a signal was received
    in the wrong thread at the wrong time due to `pcap_thread_stop()`
    canceling and waiting on threads to join again. The handling of signals
    have been improved for threaded and non-threaded operations.
  * New features:
    - Experimental CBOR DNS Stream format output, see `CBOR_DNS_STREAM.md`
    - Extended options to specify user and group to use when dropping
      privileges, see EXTENDED OPTIONS in man-page
  * Commits:
    a5fa14e Signal and threads
    3868104 Use old style C comments
    7946be5 Clarify building
    d5463b4 RPM spec and various automake fixes
    df206bf Resource data indexing and documentation
    0e2d0fe Fix #22, fix #43: Update README
    5921d73 Add stream option RLABELS and RLABEL_MIN_SIZE
    6dd6ec1 Implement experimental CBOR DNS Stream Format
    4baf695 Fix #37: Extended options to specifty user/group to use when
            dropping privileges
    61d830a Fix #35: Use `AC_HEADER_TIME` and fix warning
* Thu Dec 15 2016 Jerry Lundström <lundstrom.jerry@gmail.com> 1.2.0-1
- Initial package
