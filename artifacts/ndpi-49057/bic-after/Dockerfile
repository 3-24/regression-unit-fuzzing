FROM regression-unit-framework/base

RUN git clone --depth 1 https://github.com/json-c/json-c.git json-c
RUN git clone https://github.com/ntop/nDPI.git ndpi && cd ndpi && \
    git checkout 2edfaeba4ada90ca8771a44132d2b9cc85e45570
ADD https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz libpcap-1.9.1.tar.gz

WORKDIR $SRC/ndpi

COPY build.sh $SRC/
COPY fuzz_process_packet.c $SRC/ndpi/fuzz/