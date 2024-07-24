#!/bin/bash
set -e
set -o xtrace

cd $SRC/libhtp

sed -i 's/OLEVEL=2/OLEVEL=0/g' configure.ac

sh autogen.sh
./configure
make CFLAGS="$CFLAGS $SAVE_TEMPS" CXXFLAGS="$CXXFLAGS $SAVE_TEMPS"

$CC $CFLAGS -I. -c test/fuzz/fuzz_htp.c -o fuzz_htp.o
$CC $CFLAGS -I. -c test/test.c -o test.o
$CXX $CXXFLAGS fuzz_htp.o test.o -o $OUT/fuzz_htp ./htp/.libs/libhtp.a $LIB_FUZZING_ENGINE $FUZZER_LIB

# builds corpus
zip -r $OUT/fuzz_htp_seed_corpus.zip test/files/*.t