FROM regression-unit-framework/base

RUN git clone --depth 1 https://github.com/json-c/json-c.git json-c
RUN git clone https://github.com/ntop/nDPI.git ndpi && cd ndpi && \
    git checkout 997dce0f04816b4d8440f1cfa924a89e7cee4846
ADD https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz libpcap-1.9.1.tar.gz

COPY build.sh $SRC/
COPY fuzz_process_packet.c $SRC/ndpi/fuzz/
