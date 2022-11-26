FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y automake pkg-config libtool libpcap-dev libldns-dev zlib1g-dev libyaml-perl libssl-dev build-essential clang

COPY . /repo
WORKDIR /repo
RUN ./autogen.sh
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_rssm_save_counts.cpp -fsanitize=fuzzer,address -L /install/lib/dnscap/ -l:rssm.so -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libldns-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_rssm_save_counts
ENV LD_LIBRARY_PATH=/install/lib/dnscap
