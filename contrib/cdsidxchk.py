#!/usr/bin/env python3
#
# Copyright (c) 2016, OARC, Inc.
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

import sys
import logging
import optparse
import struct
import socket
from cbor2 import CBORDecoder;

logging.basicConfig(format='%(levelname).5s: %(module)s:%(lineno)d: '
                           '%(message)s')
log = logging.getLogger(__name__)

class SimpleValue(object):
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def __repr__(self):
        return "{}".format(self.value)

def decode_simple_value(self, fp, shareable_index=None):
    return SimpleValue(struct.unpack('>B', fp.read(1))[0])

try:
    from cbor2.types import CBORSimpleValue
except:
    CBORSimpleValue = SimpleValue
    pass

class LastValues(object):
    def __init__(self):
        self.reset()

    def reset(self):
        self.ts = None
        self.src_addr4 = None
        self.src_port4 = None
        self.dest_addr4 = None
        self.dest_port4 = None
        self.src_addr6 = None
        self.src_port6 = None
        self.dest_addr6 = None
        self.dest_port6 = None
        self.rlabel = []
        self.mlabel = []
        self.rr_type = None
        self.rr_class = None
        self.rr_ttl = None
        self.labels = {}
        self.label_len = {}
        self.label_parts = {}
        self.label_part_len = {}
        self.rdata = {}
        self.rdata_len = {}


last = LastValues()

MAX_RLABELS = 255
MIN_RLABEL_SIZE = 3

def add_label(label):
    size = 0
    if isinstance(label, list):
        for l in label:
            if isinstance(l, str) and len(l) > 2:
                if not l in last.label_parts:
                    last.label_parts[l] = 1
                    last.label_part_len[l] = len(l)
                else:
                    last.label_parts[l] += 1
            if not isinstance(l, int):
                size += len(l)
    else:
        size = len(label)
    if size < 3:
        return

    idx = "{}".format(label)
#    print(idx)

    if not idx in last.labels:
        last.labels[idx] = 1
        last.label_len[idx] = size
    else:
        last.labels[idx] += 1

def add_rdata(rdata):
    size = 0
    if isinstance(rdata, list):
        for l in rdata:
            if not isinstance(l, int):
                size += len(l)
    else:
        size = len(rdata)
    if size < 3:
        return

    idx = "{}".format(rdata)
#    print(idx)
    if not idx in last.rdata:
        last.rdata[idx] = 1
        last.rdata_len[idx] = size
    else:
        last.rdata[idx] += 1



def get_rlabel(idx):
    rlabel_idx = -idx - 1
    try:
        label = last.rlabel.pop(rlabel_idx)
        last.rlabel.insert(0, label)
        return label
    except:
        raise Exception("rlabel index {} out of range".format(rlabel_idx))

def add_rlabel(label):
    size = 0
    if isinstance(label, list):
        for l in label:
            if isinstance(l, str):
                size += len(l)
    if size < MIN_RLABEL_SIZE:
        return
    last.rlabel.insert(0, label)
    if len(last.rlabel) > MAX_RLABELS:
        last.rlabel.pop()

def build_mlabel_label(label):
    if isinstance(label, int) and label < 0:
        label = get_rlabel(label)
    else:
        add_rlabel(label)

    if isinstance(label, str):
        last.mlabel.append(label)
    elif isinstance(label, list):
        if len(label) and isinstance(label[0], int):
            last.mlabel.append(label)
            return
        label = list(label)
        while len(label):
            last.mlabel.append(list(label))
            label.pop(0)

def build_mlabel(rrs):
    for rr in rrs:
        if len(rr) and isinstance(rr[0], bool):
            continue
        if len(rr):
            build_mlabel_label(rr[0])
        if len(rr) > 1 and isinstance(rr[len(rr)-1], list):
            for l in rr[len(rr)-1]:
                build_mlabel_label(l)

def parse_label(label, lvl):
    if isinstance(label, int) and label < 0:
        label = get_rlabel(label)
    else:
        add_rlabel(label)
        add_label(label)

    if isinstance(label, bytes):
        #print((" " * lvl)+"label: {}".format(bytes))
        pass
    elif isinstance(label, list):
        if len(label) and isinstance(label[0], int) and label[0] < 0:
            dn = list(get_rlabel(label[0]))
        else:
            dn = list(label)
        #print((" " * lvl)+"clabel: {}".format(dn))
        dnstr = []
        seen_mlabel = {}
        while len(dn):
            while isinstance(dn[0], int):
                if dn[0] in seen_mlabel:
                    dn = [ "{ name compression loop }" ]
                    break
                seen_mlabel[dn[0]] = 1
                dn = list(last.mlabel[dn[0]])
            dnstr.append(dn.pop(0))
        #print((" " * lvl)+"label:  "+ " . ".join(dnstr))

    else:
        raise Exception("invalid label type {}".format(type(label)))


def parse_rrs(rrs, lvl):
    for rr in rrs:
        #print((" " * lvl)+"rr:")
        lvl+=2

        if len(rr) and isinstance(rr[0], bool):
            #print((" " * lvl)+"incomplete/broken DNS RR, no support for these yet")
            continue

        parse_label(rr.pop(0), lvl)

        bits = 0
        if isinstance(rr[0], CBORSimpleValue):
            bits = rr.pop(0).value
            #print((" " * lvl)+"type    (0): "+("yes" if bits & 1 else "no"))
            #print((" " * lvl)+"class   (1): "+("yes" if bits & 1<<1 else "no"))
            #print((" " * lvl)+"ttl     (2): "+("yes" if bits & 1<<2 else "no"))
            #print((" " * lvl)+"rdlength(3): "+("yes" if bits & 1<<3 else "no"))

        rr_type = None
        rr_class = None
        rr_ttl = None
        rdlength = None
        if not bits:
            if len(rr) > 4:
                bits = 0xff
            elif len(rr) > 1:
                raise Exception("invalid rr, expected none (0) or all (4) optional values but got {}".format(len(rr)-1))
        if bits & 1:
            if not isinstance(rr[0], int):
                raise Exception("invalid rr.type, expected int but got: {}".format(type(rr[0])))
            rr_type = rr.pop(0)
        if bits & 1<<1:
            if not isinstance(rr[0], int):
                raise Exception("invalid rr.class, expected int but got: {}".format(type(rr[0])))
            rr_class = rr.pop(0)
        if bits & 1<<2:
            if not isinstance(rr[0], int):
                raise Exception("invalid rr.ttl, expected int but got: {}".format(type(rr[0])))
            rr_ttl = rr.pop(0)
        if bits & 1<<3:
            if not isinstance(rr[0], int):
                raise Exception("invalid rr.rdlength, expected int but got: {}".format(type(rr[0])))
            rdlength = rr.pop(0)

        if not rr_type:
            rr_type = last.rr_type
        if not rr_class:
            rr_class = last.rr_class
        if not rr_ttl:
            rr_ttl = last.rr_ttl

        #print((" " * lvl)+"type: {}".format(rr_type))
        #print((" " * lvl)+"class: {}".format(rr_class))
        #print((" " * lvl)+"ttl: {}".format(rr_ttl))
        if rdlength:
            #print((" " * lvl)+"rdlength: {}".format(rdlength))
            pass

        if rr_type != 41:
            last.rr_type = rr_type
            last.rr_class = rr_class
            last.rr_ttl = rr_ttl

        if isinstance(rr[0], bytes):
            add_rdata(rr[0])
            rr.pop(0)
            #print((" " * lvl)+"rdata: "+"".join("{:02x}".format(byte) for byte in rr.pop(0)))
            pass
        elif isinstance(rr[0], list):
            add_rdata(rr[0])
            rdata = []
            for i in rr.pop(0):
                if isinstance(i, int) and i < 0:
                    i = get_rlabel(i)
                elif not isinstance(i, bytes):
                    add_rlabel(i)
                    add_label(i)

                if isinstance(i, bytes):
                    rdata.append("".join("{:02x}".format(byte) for byte in i))
                elif isinstance(i, list):
                    dn = list(i)
                    dnstr = []
                    seen_mlabel = {}
                    while len(dn):
                        while isinstance(dn[0], int):
                            if dn[0] in seen_mlabel:
                                dn = [ "{ name compression loop }" ]
                                break
                            seen_mlabel[dn[0]] = 1
                            dn = list(last.mlabel[dn[0]])
                        dnstr.append(dn.pop(0))
                    rdata.append("[ clabel: {} label: ".format(i) + " . ".join(dnstr) + " ]")
                else:
                    raise Exception("invalid rr.rdata[], expected bytes|list but got: {}".format(type(i)))

            #print((" " * lvl)+"rdata: "+" ".join(rdata))
        else:
            raise Exception("invalid rr.rdata, expected bytes|list but got: {}".format(type(rr[0])))

        lvl-=2

def parse_qrs(qrs, lvl):
    for qr in qrs:
        #print((" " * lvl)+"qr:")
        lvl+=2
        parse_label(qr.pop(0), lvl)

        rr_type = None
        rr_class = None
        if len(qr):
            if not isinstance(qr[0], int):
                raise Exception("invalid qr.type|class, expected int but got {}".format(type(qr[0])))
            if qr[0] > -1:
                rr_type = qr.pop(0)
                if len(qr):
                    if not isinstance(qr[0], int):
                        raise Exception("invalid qr.class, expected int but got {}".format(type(qr[0])))
                    elif not qr[0] < 0:
                        raise Exception("invalid qr.class, expected negative int but got positive")
                    rr_class = -qr.pop(0) - 1
            else:
                rr_class = -qr.pop(0) - 1

        if not rr_type:
            rr_type = last.rr_type
        if not rr_class:
            rr_class = last.rr_class

        #print((" " * lvl)+"type: {}".format(rr_type))
        #print((" " * lvl)+"class: {}".format(rr_class))

        if rr_type != 41:
            last.rr_type = rr_type
            last.rr_class = rr_class

        lvl-=2

def parse_dns_message(dns, lvl):
    #print((" " * lvl)+"dns:")
    lvl+=2

    if isinstance(dns[0], bool):
        #print((" " * lvl)+"incomplete/broken DNS packet, no support for these yet")
        return

    #print((" " * lvl)+"header:")
    lvl+=2
    id = dns.pop(0)
    #print((" " * lvl)+"id: {}".format(id))
    raw = dns.pop(0)
    #print((" " * lvl)+"raw: 0x{:04x}".format(raw))
    lvl+=2
    #print((" " * lvl)+"    QR: "+("yes" if raw & 1<<15 else "no"))
    #print((" " * lvl)+"Opcode: {}".format(((raw >> 11) & 0xf)))
    #print((" " * lvl)+"    AA: "+("yes" if raw & 1<<10 else "no"))
    #print((" " * lvl)+"    TC: "+("yes" if raw & 1<<9 else "no"))
    #print((" " * lvl)+"    RD: "+("yes" if raw & 1<<8 else "no"))
    #print((" " * lvl)+"    RA: "+("yes" if raw & 1<<7 else "no"))
    #print((" " * lvl)+"     Z: "+("yes" if raw & 1<<6 else "no"))
    #print((" " * lvl)+"    AD: "+("yes" if raw & 1<<5 else "no"))
    #print((" " * lvl)+"    CD: "+("yes" if raw & 1<<4 else "no"))
    #print((" " * lvl)+" RCODE: {}".format(raw & 0xf))
    lvl-=2

    bits = 0
    if isinstance(dns[0], int) and dns[0] < 0:
        bits = -dns.pop(0) - 1
        #print((" " * lvl)+"qdcount(0): "+("yes" if bits & 1 else "no"))
        #print((" " * lvl)+"ancount(1): "+("yes" if bits & 1<<1 else "no"))
        #print((" " * lvl)+"nscount(2): "+("yes" if bits & 1<<2 else "no"))
        #print((" " * lvl)+"arcount(3): "+("yes" if bits & 1<<3 else "no"))

    if not bits:
        if isinstance(dns[0], int):
            bits = 0xff

    if bits & 1:
        if not isinstance(dns[0], int):
            raise Exception("invalid dns.header.qdcount, expected int but got: {}".format(type(dns[0])))
        dns.pop(0)
        #print((" " * lvl)+"qdcount: {}".format(dns.pop(0)))
    if bits & 1<<1:
        if not isinstance(dns[0], int):
            raise Exception("invalid dns.header.ancount, expected int but got: {}".format(type(dns[0])))
        dns.pop(0)
        #print((" " * lvl)+"ancount: {}".format(dns.pop(0)))
    if bits & 1<<2:
        if not isinstance(dns[0], int):
            raise Exception("invalid dns.header.nscount, expected int but got: {}".format(type(dns[0])))
        dns.pop(0)
        #print((" " * lvl)+"nscount: {}".format(dns.pop(0)))
    if bits & 1<<3:
        if not isinstance(dns[0], int):
            raise Exception("invalid dns.header.arcount, expected int but got: {}".format(type(dns[0])))
        dns.pop(0)
        #print((" " * lvl)+"arcount: {}".format(dns.pop(0)))

    bits = 0
    if isinstance(dns[0], CBORSimpleValue):
        bits = dns.pop(0).value
        #print((" " * lvl)+"questions  (0): "+("yes" if bits & 1 else "no"))
        #print((" " * lvl)+"answers    (1): "+("yes" if bits & 1<<1 else "no"))
        #print((" " * lvl)+"authorities(2): "+("yes" if bits & 1<<2 else "no"))
        #print((" " * lvl)+"additionals(3): "+("yes" if bits & 1<<3 else "no"))

    last.mlabel = []
    rlabel = list(last.rlabel)
    for n in range(4):
        if len(dns) > n and isinstance(dns[n], list):
            build_mlabel(dns[n])
    last.rlabel = rlabel

    if not bits:
        if len(dns) > 3:
            bits = 0xff
        elif len(dns) > 0:
            raise Exception("invalid dns.message rr's, expected none (0) or all (4) but got {}".format(len(dns)))

    if bits & 1:
        if not isinstance(dns[0], list):
            raise Exception("invalid dns.message.questions, expected list but got: {}".format(type(dns[0])))
        #print((" " * lvl)+"questions:")
        parse_qrs(dns.pop(0), lvl+2)
    if bits & 1<<1:
        if not isinstance(dns[0], list):
            raise Exception("invalid dns.message.answers, expected list but got: {}".format(type(dns[0])))
        #print((" " * lvl)+"answers:")
        parse_rrs(dns.pop(0), lvl+2)
    if bits & 1<<2:
        if not isinstance(dns[0], list):
            raise Exception("invalid dns.message.authorities, expected list but got: {}".format(type(dns[0])))
        #print((" " * lvl)+"authorities:")
        parse_rrs(dns.pop(0), lvl+2)
    if bits & 1<<3:
        if not isinstance(dns[0], list):
            raise Exception("invalid dns.message.additionals, expected list but got: {}".format(type(dns[0])))
        #print((" " * lvl)+"additionals:")
        parse_rrs(dns.pop(0), lvl+2)

    if len(dns):
        if isinstance(dns[0], bytes):
            dns.pop(0)
            #print((" " * lvl)+"malformed: "+"".join("{:02x}".format(byte) for byte in dns.pop(0)))
            pass
        if len(dns):
            raise Exception("invalid dns.message, garbage at end: {}".format(dns))

def parse_ip_header(ip_header, lvl):
    #print((" " * lvl)+"ip_header:")
    lvl+=2

    #print((" " * lvl)+"bits:")
    lvl+=2
    bits = ip_header.pop(0)
    reverse = False
    if isinstance(bits, int):
        if bits < 0:
            #print((" " * lvl)+"reverse: yes")
            bits = -bits - 1
            reverse = True
        #print((" " * lvl)+"family   (0): "+("INET6" if bits & 1 else "INET"))
        #print((" " * lvl)+"have_src (1): "+("yes" if bits & 1<<1 else "no"))
        #print((" " * lvl)+"have_dest(2): "+("yes" if bits & 1<<2 else "no"))
        #print((" " * lvl)+"have_port(3): "+("yes" if bits & 1<<3 else "no"))
    else:
        raise Exception("invalid ip_header.bits, expected int but got: {}".format(type(bits)))
    lvl-=2

    src_addr = None
    dest_addr = None
    src_port = None
    dest_port = None

    if bits & 1<<1:
        src_addr = ip_header.pop(0)
        if not isinstance(src_addr, bytes):
            raise Exception("invalid ip_header.src_addr, expected bytes but got: {}".format(type(src_addr)))
    else:
        if reverse:
            src_addr = last.dest_addr6 if bits & 1 else last.dest_addr4
            if not src_addr:
                raise Exception("invalid ip_header.bits, expected to have last dest addr but don't")
        else:
            src_addr = last.src_addr6 if bits & 1 else last.src_addr4
            if not src_addr:
                raise Exception("invalid ip_header.bits, expected to have last src addr but don't")

    if bits & 1<<2:
        dest_addr = ip_header.pop(0)
        if not isinstance(dest_addr, bytes):
            raise Exception("invalid ip_header.dest_addr, expected bytes but got: {}".format(type(dest_addr)))
    else:
        if reverse:
            dest_addr = last.src_addr6 if bits & 1 else last.src_addr4
            if not dest_addr:
                raise Exception("invalid ip_header.bits, expected to have last src addr but don't")
        else:
            dest_addr = last.dest_addr6 if bits & 1 else last.dest_addr4
            if not dest_addr:
                raise Exception("invalid ip_header.bits, expected to have last dest addr but don't")

    if bits & 1<<3:
        ports = ip_header.pop(0)
        if not isinstance(ports, int):
            raise Exception("invalid ip_header.src_dest_port, expected int but got: {}".format(type(ports)))
        if ports > 0xffff:
            src_port = ports & 0xffff
            dest_port = ports >> 16
        elif ports < 0:
            if reverse:
                src_port = last.dest_port6 if bits & 1 else last.dest_port4
                if src_port == None:
                        raise Exception("invalid ip_header.bits, expected to have last dest port but don't")
            else:
                src_port = last.src_port6 if bits & 1 else last.src_port4
                if src_port == None:
                    raise Exception("invalid ip_header.bits, expected to have last src port but don't")
            dest_port = -ports - 1
        else:
            src_port = ports
            if reverse:
                dest_port = last.src_port6 if bits & 1 else last.src_port4
                if dest_port == None:
                        raise Exception("invalid ip_header.bits, expected to have last src port but don't")
            else:
                dest_port = last.dest_port6 if bits & 1 else last.dest_port4
                if dest_port == None:
                        raise Exception("invalid ip_header.bits, expected to have last dest port but don't")
    else:
        if reverse:
            src_port = last.dest_port6 if bits & 1 else last.dest_port4
            if src_port == None:
                    raise Exception("invalid ip_header.bits, expected to have last dest port but don't")
        else:
            src_port = last.src_port6 if bits & 1 else last.src_port4
            if src_port == None:
                raise Exception("invalid ip_header.bits, expected to have last src port but don't")
        if reverse:
            dest_port = last.src_port6 if bits & 1 else last.src_port4
            if dest_port == None:
                    raise Exception("invalid ip_header.bits, expected to have last src port but don't")
        else:
            dest_port = last.dest_port6 if bits & 1 else last.dest_port4
            if dest_port == None:
                    raise Exception("invalid ip_header.bits, expected to have last dest port but don't")

    #print((" " * lvl)+" src addr: " + socket.inet_ntop(socket.AF_INET6 if bits & 1 else socket.AF_INET, src_addr))
    #print((" " * lvl)+"dest addr: " + socket.inet_ntop(socket.AF_INET6 if bits & 1 else socket.AF_INET, dest_addr))
    #print((" " * lvl)+" src port: {}".format(src_port))
    #print((" " * lvl)+"dest port: {}".format(dest_port))

    if bits & 1:
        last.src_addr6 = src_addr
        last.dest_addr6 = dest_addr
        last.src_port6 = src_port
        last.dest_port6 = dest_port
    else:
        last.src_addr4 = src_addr
        last.dest_addr4 = dest_addr
        last.src_port4 = src_port
        last.dest_port4 = dest_port


def parse_message_bits(bits, lvl):
    #print((" " * lvl)+"message_bits:")
    lvl+=2
    dns = "no"
    if isinstance(bits, int):
        if bits & 1:
            dns = "yes"
        #print((" " * lvl)+"dns      (0): "+dns)

        if bits & 1<<1:
            proto = "tcp"
        elif dns == "yes":
            proto = "udp"
        else:
            proto = "icmp"
        #print((" " * lvl)+"proto    (1): "+proto)

        if bits & 1<<2:
            frag = "yes"
        else:
            frag = "no"
        #print((" " * lvl)+"frag     (2): "+frag)

        if bits & 1<<3:
            malformed = "yes"
        else:
            malformed = "no"
        #print((" " * lvl)+"malformed(3): "+malformed)

    else:
        raise Exception("invalid message_bits, expected int but got: {}".format(type(bits)))

    return 1 if dns == "yes" else 0

def parse_timestamp(ts, lvl):
    #print((" " * lvl)+"timestamp:")
    lvl+=2

    if isinstance(ts, list):
        if ts[0] < 0:
            if not last.ts:
                raise Exception("invalid timestamp.seconds, got diff from last value but have no last value")
            if not len(last.ts) == len(ts):
                raise Exception("invalid timestamp.seconds, differentialy precision missmatch")

            ts[0] = last.ts[0] + ( -ts[0] - 1 )
            #print((" " * lvl)+"seconds: {}".format(ts[0]))

            if len(ts) > 1:
                ts[1] = last.ts[1] + ts[1]
                #print((" " * lvl)+"useconds: {}".format(ts[1]))
            if len(ts) > 2:
                ts[2] = last.ts[2] + ts[2]
                #print((" " * lvl)+"nseconds: {}".format(ts[2]))
        else:
            #print((" " * lvl)+"seconds: {}".format(ts[0]))
            if len(ts) > 1:
                #print((" " * lvl)+"useconds: {}".format(ts[1]))
                pass
            if len(ts) > 2:
                #print((" " * lvl)+"nseconds: {}".format(ts[2]))
                pass
        last.ts = ts

    elif isinstance(ts, int):
        #print((" " * lvl)+"seconds: {}".format(ts))
        pass
    else:
        raise Exception("invalid timestamp, expected list|int but got: {}".format(type(ts)))

def parse(cds):
    #print("paket:")
    try:
        parse_timestamp(cds.pop(0), 2)
        is_dns = parse_message_bits(cds.pop(0), 2)
        parse_ip_header(cds, 2)
        if not is_dns:
            raise Exception("not dns? huh?")
        parse_dns_message(cds, 2)
    except IndexError as idx:
        if not str(idx) == "pop from empty list":
            raise
        #print("  ...")
    except:
        raise

def main():
    usage = '%prog [-v] [-h] <cds file...>'
    parser = optparse.OptionParser(usage, version='%prog 0.01')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose',
                      help='turn verbose mode on')

    (options, args) = parser.parse_args()

    if options.verbose == True:
        log.setLevel(logging.DEBUG)
        log.debug('argv: %s', sys.argv)
        log.debug('options: %s', options)
        log.debug('args: %s', args)
    else:
        log.setLevel(logging.WARNING)

    if not args:
        parser.print_usage()
        exit(1)

    decoder = CBORDecoder()
    # if https://github.com/agronholm/cbor2/pull/5 is not merged/released yet
    if 0 not in decoder.special_decoders:
        decoder.special_decoders[0] = lambda self, fp, shareable_index=None: SimpleValue(0)
        decoder.special_decoders[1] = lambda self, fp, shareable_index=None: SimpleValue(1)
        decoder.special_decoders[2] = lambda self, fp, shareable_index=None: SimpleValue(2)
        decoder.special_decoders[3] = lambda self, fp, shareable_index=None: SimpleValue(3)
        decoder.special_decoders[4] = lambda self, fp, shareable_index=None: SimpleValue(4)
        decoder.special_decoders[5] = lambda self, fp, shareable_index=None: SimpleValue(5)
        decoder.special_decoders[6] = lambda self, fp, shareable_index=None: SimpleValue(6)
        decoder.special_decoders[7] = lambda self, fp, shareable_index=None: SimpleValue(7)
        decoder.special_decoders[8] = lambda self, fp, shareable_index=None: SimpleValue(8)
        decoder.special_decoders[9] = lambda self, fp, shareable_index=None: SimpleValue(9)
        decoder.special_decoders[10] = lambda self, fp, shareable_index=None: SimpleValue(10)
        decoder.special_decoders[11] = lambda self, fp, shareable_index=None: SimpleValue(11)
        decoder.special_decoders[12] = lambda self, fp, shareable_index=None: SimpleValue(12)
        decoder.special_decoders[13] = lambda self, fp, shareable_index=None: SimpleValue(13)
        decoder.special_decoders[14] = lambda self, fp, shareable_index=None: SimpleValue(14)
        decoder.special_decoders[15] = lambda self, fp, shareable_index=None: SimpleValue(15)
        decoder.special_decoders[16] = lambda self, fp, shareable_index=None: SimpleValue(16)
        decoder.special_decoders[17] = lambda self, fp, shareable_index=None: SimpleValue(17)
        decoder.special_decoders[18] = lambda self, fp, shareable_index=None: SimpleValue(18)
        decoder.special_decoders[19] = lambda self, fp, shareable_index=None: SimpleValue(19)
        decoder.special_decoders[24] = decode_simple_value

    version = None

    for f in args:
        log.debug('file: %s', f)
        with open(f, 'rb') as fp:
            obj = None
            try:
                obj = decoder.decode(fp)
            except Exception as e:
                if e.__str__().find("index out of range") == -1:
                    raise
            if not isinstance(obj, list):
                raise Exception("Invalid element, expected an array but found: {}".format(type(obj)))

            version = obj.pop(0)
            if version != "CDSv1":
                raise Exception("Invalid version, expected CDSv1 but got: {}".format(version))

            while len(obj):
                opt = obj.pop(0)
                if not isinstance(opt, int):
                    raise Exception("Invalid option, expected int but got: {}".format(type(opt)))
                if opt == 0:
                    MAX_RLABELS = obj.pop(0)
                    if not isinstance(MAX_RLABELS, int) or MAX_RLABELS < 1:
                        raise Exception("Invalid option for maximum rlabels, got: {}".format(MAX_RLABELS))
                    log.debug("Using maximum rlabels {}".format(MAX_RLABELS))
                elif opt == 1:
                    MIN_RLABEL_SIZE = obj.pop(0)
                    if not isinstance(MIN_RLABEL_SIZE, int) or MIN_RLABEL_SIZE < 1:
                        raise Exception("Invalid option for minimum rlabel size, got: {}".format(MIN_RLABEL_SIZE))
                    log.debug("Using minimum rlabel size {}".format(MIN_RLABEL_SIZE))
                else:
                    raise Exception("Unknown option: {}".format(opt))

            while True:
                obj = None
                try:
                    obj = decoder.decode(fp)
                except Exception as e:
                    if e.__str__().find("index out of range") == -1:
                        raise
                if obj == None:
                    break
                if not isinstance(obj, list):
                    raise Exception("Invalid element, expected an array but found: {}".format(type(obj)))
                parse(obj)

            log.debug("unique labels: {} parts: {} rdata: {}".format(len(last.labels), len(last.label_parts), len(last.rdata)))

            n = 0
            e = 0
            for l in last.labels:
#                print("{}: {}".format(l, last.labels[l]))
                if last.labels[l] > 1:
                    n += last.label_len[l] * ( last.labels[l] - 1 )
                    e += 2 * ( last.labels[l] - 1 )
            log.debug("reduce labels: {} - {}".format(n, e))

            n = 0
            e = 0
            for l in last.label_parts:
#                print("{}: {}".format(l, last.label_parts[l]))
                if last.label_parts[l] > 1:
                    n += last.label_part_len[l] * ( last.label_parts[l] - 1 )
                    e += 2 * ( last.label_parts[l] - 1 )
            log.debug("reduce label parts: {} - {}".format(n, e))

            n = 0
            e = 0
            for l in last.rdata:
                if last.rdata[l] > 1:
                    n += last.rdata_len[l] * ( last.rdata[l] - 1 )
                    e += 2 * ( last.rdata[l] - 1 )
#                    print("{}: {}".format(l, last.rdata[l]))
            log.debug("reduce rdata: {} - {}".format(n, e))

            last.reset()

if __name__ == '__main__':
    main()
