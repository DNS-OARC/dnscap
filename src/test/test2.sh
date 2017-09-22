#!/bin/sh -xe

../dnscap -g -r dns.pcap-dist 2>no-layers.out
../dnscap -g -r dns.pcap-dist -o use_layers=yes 2>layers.out

diff no-layers.out layers.out
