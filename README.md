# dnscap

[![Build Status](https://travis-ci.org/DNS-OARC/dnscap.svg?branch=develop)](https://travis-ci.org/DNS-OARC/dnscap) [![Coverity Scan Build Status](https://scan.coverity.com/projects/10009/badge.svg)](https://scan.coverity.com/projects/dns-oarc-dnscap)

`dnscap` is a network capture utility designed specifically for DNS traffic.
It produces binary data in `pcap(3)` and other format. This utility is similar
to `tcpdump(1)`, but has a number of features tailored to DNS transactions
and protocol options. DNS-OARC uses `dnscap` for DITL data collections.

Some of its features include:
- Understands both IPv4 and IPv6
- Captures UDP, TCP, and IP fragments.
- Collect only queries, responses, or both (`-s` option)
- Collect for only certain source/destination addresses (`-a` `-z` `-A` `-Z` options)
- Periodically creates new pcap files (`-t` option)
- Spawns an upload script after closing a pcap file (`-k` option)
- Will start and stop collecting at specific times (`-B` `-E` options)

More information may be found here:
- https://www.dns-oarc.net/tools/dnscap
- https://www.dns-oarc.net/oarc/data/ditl

Issues should be reported here:
- https://github.com/DNS-OARC/dnscap/issues

Mailinglist:
- https://lists.dns-oarc.net/mailman/listinfo/dnscap-users

## Dependencies

`dnscap` has a non-optional dependency on the PCAP library and optional
dependencies on LDNS and BIND library (see also Linking with libbind).

To install the dependencies under Debian/Ubuntu:
```
apt-get install -y libpcap-dev libldns-dev libbind-dev
```

To install the dependencies under CentOS (with EPEL enabled):
```
yum install -y libpcap-devel ldns-devel bind-devel
```

For the following OS you will need to install some of the dependencies
from source or Ports, these instructions are not included.

To install some of the dependencies under FreeBSD 10+ using `pkg`:
```
pkg install -y libpcap ldns
```

To install some of the dependencies under OpenBSD 5+ using `pkg_add`:
```
pkg_add libldns
```

## Building from source tarball

The source tarball from DNS-OARC comes prepared with `configure`:

```
tar zxvf dnscap-version.tar.gz
cd dnscap-version
./configure [optiona]
make
make install
```

## Building from Git repository

If you are building `dnscap` from it's Git repository you will first need
to initiate the Git submodules that exists and later create autoconf/automake
files, this will require a build environment with Autoconf, Automake and
Libtool to be installed.

```
git clone https://github.com/DNS-OARC/dnscap.git
cd dnscap
git submodule update --init
./autogen.sh
./configure [options]
make
make install
```

## Linking with libbind

If you plan to use dnscap's -x/-X features, then you might need
to have libbind installed.   These features use functions such
as ns_parserr().  On some systems these functions will be found
in libresolv.  If not, then you might need to install libbind.
I suggest first building dnscap on your system as-is, then run

```$ ./dnscap -x foo```

If you see an error, install libbind either from your
OS package system or by downloading the source from
http://www.isc.org/downloads/current

## 64-bit libraries

If you need to link against 64-bit libraries found in non-standard
locations, provide the location by setting LDFLAGS before running
configure:

```$ env LDFLAGS=-L/usr/lib64 ./configure```


## FreeBSD (and other BSDs?)

If you've installed libbind for -x/-X then it probably went into
/usr/local and you'll need to tell configure how to find it:

```$ env CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure```

Also note that we have observed significant memory leaks on FreeBSD
(7.2) when using -x/-X.  To rectify:

1. cd /usr/ports/dns/libbind
1. make config
1. de-select "Compile with thread support"
1. reinstall the libbind port
1. recompile and install dnscap

## CBOR DNS Stream Format

This is an experimental format for representing DNS information in CBOR
with the goals to:
- Be able to stream the information
- Support incomplete, broken and/or invalid DNS
- Have close to no data quality and signature degradation
- Support additional non-DNS meta data (such as ICMP/TCP attributes)

Read [CBOR_DNS_STREAM.md](https://github.com/DNS-OARC/dnscap/blob/develop/CBOR_DNS_STREAM.md) for more information.

To enable this output please follow the instructions below for Enabling
CBOR Output, note that this only requires Tinycbor.

### Outputting to CBOR DNS Stream (CDS)

To output to the CDS format you tell `dnscap` to write to a file and set
the format to CDS.  CDS is a stream of CBOR objects and you can control how
many objects are kept in memory until flushed to the file by setting
`cds_cbor_size`, note that this is bytes of memory and not number of objects.
When it reaches this limit it will write the output and start on a new file.
Read `dnscap`'s man page for all CDS extended options.

```
src/dnscap [...] -w <file> -F cds [ -o cds_cbor_size=<bytes> ]
```

## CBOR

There is experimental support for CBOR output using LDNS and Tinycbor with
a data structure described in the DNS-in-JSON draft.

https://datatracker.ietf.org/doc/draft-hoffman-dns-in-json/

### Enabling CBOR Output

To enable the CBOR output support you will need to install it's dependencies
before running `configure`, LDNS exists for most distributions but Tinycbor
is new so you need to download and compile it, you do not necessary need to
install it as shown in the example below.

```sh
git clone https://github.com/DNS-OARC/dnscap.git
cd dnscap
git submodule update --init
git clone https://github.com/01org/tinycbor.git
cd tinycbor
git checkout v0.4
make
cd ..
sh autogen.sh
CFLAGS="-I$PWD/tinycbor/src" LDFLAGS="-L$PWD/tinycbor/lib" LIBS="-ltinycbor" ./configure
make
```

**NOTE**: Paths in `CFLAGS` and `LDFLAGS` must be absolute.

### CBOR to JSON

Tinycbor comes with a tool to convert CBOR to JSON, check `bin/cbordump -h`
in the Tinycbor directory after having compiled it.

### Outputting to CBOR

To output to the CBOR format you tell `dnscap` to write to a file and set
the format to CBOR.  Since Tinycbor constructs everything in memory there
is a limit and when it is reached it will write the output and start on a
new file.  You can control the number of bytes with the extended option
`cbor_chunk_size`.

```
src/dnscap [...] -w <file> -F cbor [ -o cbor_chunk_size=<bytes> ]
```

### Additional attributes

There is currently an additional attribute added to the CBOR object which
contains the IP information as following:

```
"ip": [
  <proto>,
  "<source ip address>",
  <source port>
  "<destination ip address>",
  <destination port>
]
```

Example:

```json
"ip": [
  17,
  "127.0.0.1",
  34856,
  "127.0.0.1",
  53
]
```

### Limitations, deviations and issues

Since this is still experimental there are of course some issues:
- RDATA is in binary format
- DNS packet are parsed by LDNS which can fail if malformed packets
- `dateSeconds` is added as a C `double` which might loose some of the time percision
