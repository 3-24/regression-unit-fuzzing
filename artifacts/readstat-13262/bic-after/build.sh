#!/bin/bash
set -e
set -o xtrace

# sed -i '603d' $SRC/readstat/src/sas/readstat_sas7bdat_read.c
# sed -i '603i { fprintf(stderr, "[BugOSS] src/sas/readstat_sas7bdat_read.c:603\\n"); goto cleanup; }' $SRC/readstat/src/sas/readstat_sas7bdat_read.c

cd $SRC/readstat

./autogen.sh
CFLAGS="$CFLAGS -Wno-implicit-const-int-float-conversion"
CXXFLAGS="$CXXFLAGS -Wno-implicit-const-int-float-conversion"

WLLVM_CONFIGURE_ONLY=1 ./configure --enable-static
make clean

make CFLAGS="$CFLAGS $SAVE_TEMPS" CXXFLAGS="$CXXFLAGS $SAVE_TEMPS"
make generate_corpus
./generate_corpus

#zip $OUT/fuzz_format_dta_seed_corpus.zip corpus/dta*/test-case-*
#zip $OUT/fuzz_format_por_seed_corpus.zip corpus/por/test-case-*
#zip $OUT/fuzz_format_sav_seed_corpus.zip corpus/sav*/test-case-* corpus/zsav/test-case-*
#zip $OUT/fuzz_format_sas7bcat_seed_corpus.zip corpus/sas7bcat/test-case-*
zip $OUT/fuzz_format_sas7bdat_seed_corpus.zip corpus/sas7bdat*/test-case-*
#zip $OUT/fuzz_format_xport_seed_corpus.zip corpus/xpt*/test-case-*

READSTAT_FUZZERS="fuzz_format_sas7bdat"

for fuzzer in $READSTAT_FUZZERS; do
    make ${fuzzer} CFLAGS="$CFLAGS $FUZZER_LIB" CXXFLAGS="$CXXFLAGS $FUZZER_LIB"
    cp ${fuzzer} $OUT/${fuzzer}
done