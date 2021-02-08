#!/bin/sh -xe

../dnscap -g -T -r 1qtcppadd.pcap-dist 2>padding-no-layers.out
../dnscap -g -T -r 1qtcppadd.pcap-dist -o use_layers=yes 2>padding-layers.out

diff padding-no-layers.out padding-layers.out
