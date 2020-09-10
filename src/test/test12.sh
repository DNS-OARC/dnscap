#!/bin/sh -xe

if ! ../dnscap -g -r dns.pcap-dist -w test12 -W .gz 2>test12.out; then
    grep -qF "gzip compression requested but not supported" test12.out && exit 0
    exit 1
fi
