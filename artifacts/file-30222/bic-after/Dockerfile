FROM regression-unit-framework/base

RUN git clone https://github.com/file/file.git file && cd file && \
    git checkout 6de3683de955277c4be4be350ec683b3203d3f31

COPY build.sh magic_fuzzer.cc $SRC/
