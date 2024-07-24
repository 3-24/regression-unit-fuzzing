cp $SRC/fuzz_htp.c $SRC/libhtp/test/fuzz
cp $SRC/fuzz_htp.h $SRC/libhtp/test/fuzz

CXXFLAGS=$(echo $CXXFLAGS | sed 's/\-O1/\-O0/g')
CFLAGS=$(echo $CFLAGS | sed 's/\-O1/\-O0/g')
export CXXFLAGS=$CXXFLAGS
export CFLAGS=$CFLAGS

cd $SRC/libhtp

sed -i 's/OLEVEL=2/OLEVEL=0/g' configure.ac 

sh autogen.sh
./configure
make

$CC $CFLAGS -I. -c test/fuzz/fuzz_htp.c -o fuzz_htp.o
$CC $CFLAGS -I. -c test/test.c -o test.o
$CXX $CXXFLAGS fuzz_htp.o test.o -o $OUT/fuzz_htp ./htp/.libs/libhtp.a $LIB_FUZZING_ENGINE -lz -llzma

# builds corpus
zip -r $OUT/fuzz_htp_seed_corpus.zip test/files/*.t