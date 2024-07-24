#!/bin/bash

set -e
set -o xtrace

#sed -i 's/\-O/\-O0/g' src/Makefile.std

autoreconf -i
./configure --enable-static --disable-shared
make V=1 all CFLAGS="$CFLAGS $SAVE_TEMPS" CXXFLAGS="$CXXFLAGS $SAVE_TEMPS"

$CXX $CXXFLAGS -std=c++11 -Isrc/ \
     $SRC/magic_fuzzer.cc -o $OUT/magic_fuzzer \
     $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a $FUZZER_LIB

cp ./magic/magic.mgc $OUT/
zip -j $OUT/magic_fuzzer_seed_corpus.zip ./tests/*.testfile
