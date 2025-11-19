#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD
OUT_DIR=$SCRIPT_DIR/smake

# ================================
# FIXME this area
EXTRA_FLAGS=""
SPARROW_DIR=$BUILD_DIR/sparrow/*.i

function build() {
    cmake -G "Unix Makefiles" && make
}
# ================================

DEFAULT_FLAGS="-g -fno-omit-frame-pointer -Wno-error"

export CC="clang"
export CXX="clang++"
export CMAKE_EXPORT_COMPILE_COMMANDS=1
export CFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"
export CXXFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"

# Build
cd $SCRIPT_DIR
cp -rf $SRC_DIR $BUILD_DIR
cd $BUILD_DIR && build

# Smake
cd $BUILD_DIR
make clean
/smake/scmake --cmake-out tempo

# Copy
cd $SCRIPT_DIR
mkdir -p $OUT_DIR
cp -r $SPARROW_DIR $OUT_DIR || exit 1
d_files="jcstest.i jpegtran.i rdjpgcom.i tjbench.i tjexample.i tjunittest.i wrjpgcom.i djpeg.i"
for d_file in $d_files; do
    rm $OUT_DIR/$d_file || exit 1
done

cd $SCRIPT_DIR
patch -p1 -d $OUT_DIR < $SCRIPT_DIR/patches/cjpeg-1.5.90.patch

rm -rf $BUILD_DIR