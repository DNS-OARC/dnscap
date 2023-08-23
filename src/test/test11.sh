#!/bin/sh -xe

test -e dns.pcap || ln -s "$srcdir/dns.pcap" dns.pcap

../dnscap -?
! ../dnscap -j

! ../dnscap -o testing
! ../dnscap -o testing=
! ../dnscap -o testing=a
../dnscap -o user=user -o user=user -o group=group -o group=group \
  -o dump_format=pcap -o dump_format=cbor -o dump_format=cds \
  -F pcap -F cbor -F cds \
  -?
../dnscap -b -N -p -d -1 -I -i fake -m q -m u -m n -s i -s r -h i -h r \
  -e n -e y -e t -e f -e s -e x -e i -e r -w - -W a -W a -t 1 -c 1 -C 1 \
  -x '.*' -S -U fake -U fake -M -D -?
../dnscap -w fake -k false -?
! ../dnscap -m X
! ../dnscap -s X
! ../dnscap -h X
! ../dnscap -e X
! ../dnscap -k false
! ../dnscap -F invalid
! ../dnscap -t invalid
! ../dnscap -c invalid
! ../dnscap -C invalid
! ../dnscap -x '('
! ../dnscap -B invalid
! ../dnscap -E invalid
! ../dnscap -P invalid
if ! ../dnscap -y -? 2>test11.out; then
    grep -qF "seccomp-bpf not enabled" test11.out
fi
! ../dnscap -w fake -o use_layers=yes
! ../dnscap -g -f -h i
! ../dnscap -g -l 1 -L 1
! ../dnscap -g -b -d -g
! ../dnscap -g -b -g
! ../dnscap -g -B "2020-01-01 00:00:00" -E "2019-01-01 00:00:00"
! ../dnscap -g -o defrag_ipv4=yes
! ../dnscap -g -o defrag_ipv6=yes
! ../dnscap -g -o reassemble_tcp_bfbparsedns=yes

../dnscap -V

../dnscap -r dns.pcap -g -ddddd
../dnscap -r dns.pcap -x '.*' -X '.*' -g -ddddd

! ../dnscap -r dns.pcap -i fake 2>test11.out
cat test11.out
grep -qF -- "-i makes no sense after -r" test11.out
! ../dnscap -i fake -r dns.pcap 2>test11.out
cat test11.out
grep -qF -- "-r makes no sense after -i" test11.out

all_opts=
for opt in cbor_chunk_size cds_cbor_size cds_message_size cds_max_rlabels \
cds_min_rlabel_size cds_rdata_index_min_size cds_rdata_rindex_size \
cds_rdata_rindex_min_size pcap_buffer_size max_ipv4_fragments \
max_ipv6_fragments max_ipv6_fragments_per_packet reassemble_tcp_faultreset; \
do
    ! ../dnscap -o "$opt=0"
    all_opts="$all_opts -o $opt=1"
done

../dnscap $all_opts -?

all_opts=
for opt in cds_use_rdata_rindex cds_use_rdata_index defrag_ipv6 \
reassemble_tcp_bfbparsedns bpf_hosts_apply_all; \
do
    ! ../dnscap -o "$opt=f"
    all_opts="$all_opts -o $opt=yes"
done

../dnscap $all_opts -?

! ../dnscap -l 0 -l 4095 -l 4096
! ../dnscap -L 0 -L 4095 -L 4096
! ../dnscap -u 5353 -u 65536
