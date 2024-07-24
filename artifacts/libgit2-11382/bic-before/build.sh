#!/bin/bash

set -e
set -o xtrace

rm -rf build
mkdir -p build
cd build

cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_CLAR=OFF \
      -DUSE_HTTPS=OFF \
      -DUSE_SSH=OFF \
      -DUSE_BUNDLED_ZLIB=ON \

make -j$(nproc)
make install

for fuzzer in ../fuzzers/*_fuzzer.c
do
    fuzzer_name=$(basename "${fuzzer%.c}")

    $CC $CFLAGS -c -I"$WORK/include" -I"$SRC/libgit2/src" \
        -DLIBGIT2_NO_FEATURES_H \
        "$fuzzer" -o "$WORK/$fuzzer_name.o"
    
    $CXX $CXXFLAGS -std=c++11 -o "$OUT/$fuzzer_name" \
        $LIB_FUZZING_ENGINE "$WORK/$fuzzer_name.o" $FUZZER_LIB
    
    zip -j "$OUT/${fuzzer_name}_seed_corpus.zip" \
        ../fuzzers/corpora/${fuzzer_name%_fuzzer}/*
done