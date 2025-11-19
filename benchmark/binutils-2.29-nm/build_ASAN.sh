#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD

# ================================
# FIXME this area
BIN_OPT=""
BIN_NAME="nm"
BUG_NAMES="2017-14940"
BIN_PATH=$BUILD_DIR/binutils/$BIN_NAME-new

function build() {
    CONFIG_OPTIONS="--disable-shared --disable-gdb \
                    --disable-libdecnumber --disable-readline \
                    --disable-sim --disable-ld"
    ./configure $CONFIG_OPTIONS || exit 1
    make -j || exit 1
}
# ================================

DEFAULT_FLAGS="-g -fno-omit-frame-pointer -Wno-error"
EXTRA_FLAGS="-fsanitize=address $BIN_OPT"

export CC="clang"
export CXX="clang++"
export CMAKE_EXPORT_COMPILE_COMMANDS=1
export CFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"
export CXXFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"

BIN_DIR=$SCRIPT_DIR/asan
mkdir -p $BIN_DIR

for BUG_NAME in $BUG_NAMES; do
  # Build
  cd $SCRIPT_DIR
  cp -rf $SRC_DIR $BUILD_DIR
  cd $BUILD_DIR && build

  # Copy
  cp $BIN_PATH $BIN_DIR/$BIN_NAME-$BUG_NAME || exit 1

  rm -rf $BUILD_DIR
done
