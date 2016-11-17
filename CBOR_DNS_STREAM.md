# CBOR DNS Stream Format version 1 (CDSv1)

This is an experimental format for representing DNS information in CBOR
with the goals to:
- Be able to stream the information
- Support incomplete, broken and/or invalid DNS
- Have close to no data quality and signature degradation
- Support additional non-DNS meta data (such as ICMP/TCP attributes)

## Overview

In CBOR you are expected to have one root element, most likely an array or
map.  This format does not have a root element, instead you are expected to
read one CBOR array element at a time as a stream of CBOR elements with the
first array element being the stream initiator object.

```
[stream_init]
[message]
...
[message]
```

Here are some number on the compression rate compared to PCAP:

Uncompressed | PCAP       | CDS       | Factor
-------------|------------|-----------|-------
client       | 458373     | 133640    | 0,2915
zonalizer    | 51769844   | 9450475   | 0,1825
large ditl   | 1003931674 | 298167709 | 0,2970
small ditl   | 1651252    | 603314    | 0,3653

Gzipped      | PCAP       | CDS       | Factor  | F/Uncompressed
-------------|------------|-----------|---------|---------------
client       | 108136     | 45944     | 0,4248  | 0,1002
zonalizer    | 12468329   | 2485620   | 0,1993  | 0,0480
large ditl   | 327227203  | 117569598 | 0,3592  | 0,1171
small ditl   | 539323     | 253402    | 0,4698  | 0,1534

Xzipped      | PCAP       | CDS       | Factor  | F/Uncompressed
-------------|------------|-----------|---------|---------------
client       | 76248      | 36308     | 0,4761  | 0,0792
zonalizer    | 7894356    | 1695920   | 0,2148  | 0,0327
large ditl   | 267031412  | 86747604  | 0,3248  | 0,0864
small ditl   | 442260     | 206596    | 0,4671  | 0,1251

- `client` is a couple of hours of DNS from my workstation
- `zonalizer` is half a day from [Zonalizer](https://zonalizer.makeinstall.se) which continuously tests gTLDs
- `large ditl`, `small ditl` are capture from [DITL](https://www.dns-oarc.net/oarc/data/ditl)

## Types

- `int`: A CBOR integer (major type 0x00)
- `uint`: A CBOR integer (value >= 0, major type 0x00)
- `nint`: A CBOR negative integer (value < 0, major type 0x00), this type has special meaning see `Negative Integers`
- `simple`: A CBOR simple value (major type 0xe0)
- `bytes`: A CBOR byte string (major type 0x40)
- `string`: A CBOR UTF-8 string (major type 0x60)
- `any`: Any CBOR value
- `bool`: A CBOR boolean
- `rindex`: A CBOR negative integer that is a reverse index, see `Deduplication`

## Special Keywords

- `union`: Can be used to merge the given array or map into the current object
- `optional`: The attribute or object reference is optional

## Negative Integers

CBOR encodes negative numbers in a special way and this format uses that
for none negative number to tell them apart.

Because of that, all negative numbers needs special decoding:

```
value = -value - 1
```

## Objects

The object code below uses:
- `[` and `]` to indicate the start and end of an array
- `type name` per object attribute
- `name` per object reference
- `...` to indicate a list of previous definition
- `(`, `|` and `)` to indicate list of various types that the attribute can be

### stream_init

The initial object in the stream.

```
[
    string version,
    union stream_option option,
    ...
]
```

- `version`: The version of the format
- `option`: A list of stream option objects

### stream_option

A stream option that can specify critical information about the stream and
how it should be decoded, see `Stream Options` for more information.

```
[
    uint option_type,
    optional any option_value
]
```

- `option_type`: The type of option represented as a number
- `option_value`: The option value

### message

A message object that describes various DNS packets or other information.

```
[
    optional bool is_complete,
    union timestamp timestamp,
    simple message_bits,
    union ip_header ip_header,
    union ( icmp_message | udp_message | tcp_message | dns_message ) content
]
```

- `is_complete`: Will exist and be false if the message is not complete and following attributes may not exists
- `timestamp`: A timestamp object
- `message_bits`: Bitmap indicating message content
  - Bit 0: 0=Not DNS 1=DNS
  - Bit 1: if DNS: 0=UDP 1=TCP else: 0=ICMP/ICMPv6 1=TCP
  - Bit 2: Fragmented (0=no 1=yes)
  - Bit 3: Malformed (0=no 1=yes)
- `ip_header`: An IP header object
- `content`: The message content, may be an ICMP, UDP, TCP or DNS message object

### timestamp

The timestamp object of a message.

```
[
    ( uint seconds | nint diff_from_last ),
    optional uint useconds
    optional uint nseconds
]
```

- `seconds`: The seconds of a UNIX timestamp
- `diff_from_last`: The differentially from last `timestamp.seconds`
- `useconds`: The microseconds of a UNIX timestamp or if `diff_from_last` is used it will be the differentially from last `timestamp.useconds`
- `nseconds`: The nanoseconds of a UNIX timestamp or if `diff_from_last` is used it will be the differentially from last `timestamp.nseconds`

### ip_header

The IP header of a message.

```
[
    ( uint | nint ) ip_bits,
    optional bytes src_addr,
    optional bytes dest_addr,
    optional ( uint | nint ) src_dest_port
]
```

- `ip_bits`: Bitmap indicating IP header content, if the type is `nint` it also indicates that it is a reverse from last, see `Deduplication` for more information
  - Bit 0: address family (0=AF_INET, 1=AF_INET6)
  - Bit 1: src_addr present
  - Bit 2: dest_addr present
  - Bit 3: port present
- `src_addr`: The source address with length specifying address family, 4 bytes is IPv4 and 16 is IPv6
- `dest_addr`: The destination address with length specifying address family, 4 bytes is IPv4 and 16 is IPv6
- `src_dest_port`: A combined source and destination port, see `Source And Destination Port`

#### Source And Destination Port

The source and destination port are combined into one value.  If both source
and destination exists then the value is larger then 65535, the destination
will be the high 16 bits and source the low otherwise it will only be the
source.  If the value is negative then only the destination exists.

```
if value > 0xffff then
    src_port = value & 0xffff
    dest_port = value >> 16
else if value < 0 then
    dest_port = -value - 1
else
    src_port = value
```

### icmp_message

`if ip_header.ip_bits.1=0 && ip_header.ip_bits.2=0`

```
[
    uint type,
    uint code
]
```

- `type`: TODO
- `code`: TODO

### udp_message

`if ip_header.ip_bits.1=1 && ip_header.ip_bits.2=0`

TODO

### tcp_message

`if ip_header.ip_bits.2=1`

```
[
    uint seq_nr,
    uint ack_nr,
    uint tcp_bits,
    uint window
]
```

- `seq_nr`: TODO
- `ack_nr`: TODO
- `tcp_bits`: TODO
  - 0: URG
  - 1: ACK
  - 2: PSH
  - 3: RST
  - 4: SYN
  - 5: FIN
- `window`: TODO

### dns_message

A DNS packet.

```
[
    optional bool is_complete,
    uint id,
    uint raw_dns_header,        # TODO
    optional nint count_bits,
    optional uint qdcount,
    optional uint ancount,
    optional uint nscount,
    optional uint arcount,
    optional simple rr_bits,
    optional [
        dns_question question,
        ...
    ],
    optional [
        resource_record answer,
        ...
    ],
    optional [
        resource_record authority,
        ...
    ],
    optional [
        resource_record additional,
        ...
    ],
    optional bytes malformed
]
```

- `is_complete`: Will exist and be false if the message is not complete and following attributes may not exists
- `id`: DNS identifier
- `raw_dns_header`: TODO
- `count_bits`: Bitmap indicating which counts are present, see `Negative Integers` and `Deduplication`
  - Bit 0: qdcount present
  - Bit 1: ancount present
  - Bit 2: nscount present
  - Bit 3: arcount present
- `qdcount`: Number of question records if different from the number of entries in `question`
- `ancount`: Number of answer resource records if different from the number of entries in `answer`
- `nscount`: Number of authority resource records if different from the number of entries in `authority`
- `arcount`: Number of additional resource records if different from the number of entries in `additional`
- `question`: The question records
- `answer`: The answer resource records
- `authority`: The authority resource records
- `additional`: The additional resource records
- `malformed`: Holds the bytes of the message that was not parsed

### question

A DNS question record.

```
[
    optional bool is_complete,
    ( bytes | compressed_name | rindex ) qname,
    optional uint qtype,
    optional nint qclass
]
```

- `is_complete`: Will exist and be false if the message is not complete and following attributes may not exists
- `qname`: The QNAME as byte string, a name compression object or a reverse index, see `Deduplication`
- `qtype`: The QTYPE, see `Deduplication`
- `qclass`: The QCLASS, see `Negative Integers` and `Deduplication`

### compressed_name

An compressed name which has references to other labels within the same message.

```
[
    ( bytes label | uint label_index | nint offset | simple extension_bits ),
    ...
]
```

- `label`: A byte string with a label part
- `label_index`: An index to the N byte string label in the message
- `offset`: The offset specified in the DNS message which could not be translated into a label index
- `extension_bits`: The extension bits if not 0b00 or 0b11 # TODO: add the extension bits

### resource_record

A DNS resource record.

```
[
    optional bool is_complete,
    ( bytes | compressed_name | rindex ) name,
    optional simple rr_bits,
    optional uint type,
    optional uint class,
    optional uint ttl,
    optional uint rdlength,
    ( bytes | mixed_rdata ) rdata
]
```

- `is_complete`: Will exist and be false if the message is not complete and following attributes may not exists
- `name`:
- `rr_bits`: Bitmap indicating what is present, see `Deduplication`
  - Bit 0: type
  - Bit 1: class
  - Bit 2: ttl
  - Bit 3: rdlength     # TODO: reverse index for TTL?
- `type`: The resource record type
- `class`: The resource record class
- `ttl`: The resource record ttl
- `rdlength`: The resource record rdata length
- `rdata`: The resource record data

### mixed_rdata

An array mixed with resource data and compressed names.

```
[
    ( bytes | compressed_name ) rdata_part,
    ...
]
```
- `rdata_part`: The parts of the resource records data

## Stream Options

Each option is specified here as OptionName(OptionNumber) and optional
OptionValue type.

- `RLABELS(0) uint`: Indicates how many labels should be stored in the reverse label index before discarding them
- `RLABEL_MIN_SIZE(1) uint`: The minimum size a label must be to be put in the reverse label index
- `RDATA_RINDEX_SIZE(2) uint`: Indicates how many rdata should be stored in the reverse rdata index before discarding them
- `RDATA_RINDEX_MIN_SIZE(3) uint`: The minimum size a rdata must be to be put in the reverse rdata index
- `USE_RDATA_INDEX(4)`: If present then the stream uses rdata indexing
- `RDATA_INDEX_MIN_SIZE(5) uint`: The minimum size a rdata must be to be put in the rdata index

## Deduplication

Deduplication is done in a few different ways, data may be left out to
indicate that it is the same as the previous value, an index may be used to
indicate that it is the same as the N previous value and a reverse index
may be used to indicate that it is the N previous value looking backwards
across the stream.

In other words, using the index deduplication you will need to build a table
of the values you come across during the decoding of the stream, this table
can grow very large.

As an smaller alternative a reverse index can indicate often used data from
the N previous value looking back over the stream. This type of index also
reorder itself to try and put the most used data always in the index.

TODO: details of each attribute and it's deduplication
