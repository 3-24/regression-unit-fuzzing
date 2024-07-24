FROM regression-unit-framework/base

RUN git clone https://github.com/OISF/libhtp.git libhtp && cd libhtp && \
    git checkout 203beeef05f8c7bedd4692b35cf2fbe38c9330b8

COPY build.sh /src/
COPY *.cc *.h *.dict /src/