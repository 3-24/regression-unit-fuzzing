#!/bin/bash
set -e
set -o xtrace

# build libpcap
cd $SRC
tar -xvzf libpcap-1.9.1.tar.gz
cd libpcap-1.9.1
./configure --disable-shared --prefix="$WORK"
make -j$(nproc)
make install

cd $SRC/json-c
rm -rf build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_LIBS=OFF ..
make install

# build project
cd $SRC/ndpi
WLLVM_CONFIGURE_ONLY=1 sh autogen.sh

# if cc is gcc, omit --enable-fuzztargets
if [ $CC = "gcc" ]; then
    ENABLE_FUZZTARGETS=""
else
    ENABLE_FUZZTARGETS="--enable-fuzztargets"
fi

WLLVM_CONFIGURE_ONLY=1 ./configure $ENABLE_FUZZTARGETS \
    LIBS="$WORK/lib/libjson-c.a $WORK/lib/libpcap.a" \
    LDFLAGS="-L$WORK/lib" \
    CPPFLAGS="-I$WORK/include" \
    CFLAGS="$CFLAGS $SAVE_TEMPS" CXXFLAGS="$CXXFLAGS $SAVE_TEMPS" \

make -j$(nproc)
ls fuzz/fuzz* | grep -v "\." | grep -v "with_main" | while read i; do cp $i $OUT/; done