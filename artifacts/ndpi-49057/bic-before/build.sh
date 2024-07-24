#!/bin/bash
set -e
set -o xtrace

# build libpcap
tar -xvzf libpcap-1.9.1.tar.gz
cd libpcap-1.9.1
./configure --disable-shared --prefix="$WORK"
make -j$(nproc)
make install
cd ..

cd json-c
rm -rf build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_LIBS=OFF ..
make install
cd ../..

# build project
cd $SRC/ndpi
WLLVM_CONFIGURE_ONLY=1 sh autogen.sh


WLLVM_CONFIGURE_ONLY=1 ./configure --enable-fuzztargets \
    LIBS="$WORK/lib/libjson-c.a $WORK/lib/libpcap.a" \
    LDFLAGS="-L$WORK/lib" \
    CPPFLAGS="-I$WORK/include"

make CFLAGS="$CFLAGS $SAVE_TEMPS" CXXFLAGS="$CXXFLAGS $SAVE_TEMPS"
ls fuzz/fuzz* | grep -v "\." | grep -v "with_main" | while read i; do cp $i $OUT/; done