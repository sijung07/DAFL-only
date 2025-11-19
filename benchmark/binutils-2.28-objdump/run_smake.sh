#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD
OUT_DIR=$SCRIPT_DIR/smake

# ================================
# FIXME this area
EXTRA_FLAGS=""
SPARROW_DIR="$BUILD_DIR/sparrow/binutils/objdump"

function build() {
    CONFIG_OPTIONS="--disable-shared --disable-gdb \
                    --disable-libdecnumber --disable-readline \
                    --disable-sim --disable-ld"
    ./configure $CONFIG_OPTIONS || exit 1
    make -j || exit 1
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
yes | /smake/smake --init
/smake/smake -j 1

# Copy
cd $SCRIPT_DIR
cp -r $SPARROW_DIR $OUT_DIR || exit 1

rm -rf $BUILD_DIR