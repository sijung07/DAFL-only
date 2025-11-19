#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD

# ================================
# FIXME this area
BIN_OPT=""
BIN_NAME="swftophp"
BUG_NAMES="2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729"
BIN_PATH="$BUILD_DIR/util/swftophp"

function build() {
    ./autogen.sh && ./configure --disable-shared --disable-freetype && make
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