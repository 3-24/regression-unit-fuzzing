FROM regression-unit-framework/base

RUN git clone https://github.com/OISF/libhtp.git libhtp && cd libhtp && \
    git checkout 3c6555078ec30e0baa4855ec69d55a22fc8d3589

COPY build.sh $SRC/
COPY fuzz_htp.c fuzz_htp.h $SRC/libhtp/test/fuzz/