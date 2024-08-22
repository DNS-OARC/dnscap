# dnscap

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnscap&metric=bugs)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnscap) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnscap&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnscap)

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

General support and discussion:
- Mattermost: https://chat.dns-oarc.net/community/channels/oarc-software
- mailing-list: https://lists.dns-oarc.net/mailman/listinfo/dnscap-users

## Dependencies

`dnscap` requires a couple of libraries beside a normal C compiling
environment with autoconf, automake, libtool and pkgconfig.

`dnscap` has a non-optional dependency on the PCAP library and LDNS.

To install the dependencies under Debian/Ubuntu:
```
apt-get install -y libpcap-dev libldns-dev zlib1g-dev libyaml-perl libssl-dev
```

To install the dependencies under CentOS (with EPEL/PowerTools enabled):
```
yum install -y libpcap-devel ldns-devel openssl-devel zlib-devel perl-YAML
```

For the following OS you will need to install some of the dependencies
from source or Ports, these instructions are not included.

To install some of the dependencies under FreeBSD 10+ using `pkg`:
```
pkg install -y libpcap ldns p5-YAML openssl-devel
```

To install some of the dependencies under OpenBSD 5+ using `pkg_add`:
```
pkg_add libldns p5-YAML
```

NOTE: It is recommended to install the PCAP library from source/ports on
OpenBSD since the bundled version is an older and modified version.

### Dependencies for `cryptopant.so` plugin

For this plugin a library call `cryptopANT` is required and the original
can be found here: https://ant.isi.edu/software/cryptopANT/index.html .

For DNS-OARC packages we build our own fork, with slight modifications to
conform across distributions, of this library which is included in the same
package repository as `dnscap`. The modifications and packaging files can be
found here: https://github.com/DNS-OARC/cryptopANT .

## Building from source tarball

The [source tarball from DNS-OARC](https://www.dns-oarc.net/tools/dnscap)
comes prepared with `configure`:

```
tar zxvf dnscap-version.tar.gz
cd dnscap-version
./configure [options]
make
make install
```

## Building from Git repository

If you are building `dnscap` from it's Git repository you will first need
to initiate the Git submodules that exists and later create autoconf/automake
files, this will require a build environment with autoconf, automake, libtool
and pkg-config to be installed.

```
git clone https://github.com/DNS-OARC/dnscap.git
cd dnscap
git submodule update --init
./autogen.sh
./configure [options]
make
make install
```

### 64-bit libraries

If you need to link against 64-bit libraries found in non-standard
locations, provide the location by setting LDFLAGS before running
configure:

```
$ env LDFLAGS=-L/usr/lib64 ./configure
```

### OpenBSD

For OpenBSD you probably installed libpcap in `/usr/local` so you will need
to tell `configure` where to find the libraries and header files:

```
$ env CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib" ./configure
```

## Plugins

`dnscap` comes bundled with a set of plugins, see `-P` option.

- `anonaes128.so`: Anonymize IP addresses using AES128
- `anonmask.so`: Pseudo-anonymize IP addresses by masking them
- `cryptopan.so`: Anonymize IP addresses using an extension to Crypto-PAn (College of Computing, Georgia Tech) made by David Stott (Lucent)
- `cryptopant.so`: Anonymize IP addresses using cryptopANT, a different implementation of Crypto-PAn made by the ANT project at USC/ISI
- `ipcrypt.so`: Anonymize IP addresses using ipcrypt create by Jean-Philippe Aumasson
- `pcapdump.so`: Dump DNS into a PCAP with some filtering options
- `royparse.so`: Splits a PCAP into two streams; queries in PCAP format and responses in ASCII format
- `rssm.so`: Root Server Scaling Measurement plugin, see it's [README.md](plugins/rssm/README.md) for more information
- `rzkeychange.so`: RFC8145 key tag signal collection and reporting plugin
- `txtout.so`: Dump DNS as one-line text
- `eventlog.so`: Syslog style output for easy parsing, use with a SIEM, etc.

There is also a `template` plugin in the source repository to help others
develop new plugins.

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
git checkout v0.4.2
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
- `dateSeconds` is added as a C `double` which might loose some of the time precision
