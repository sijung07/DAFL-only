#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD

# ================================
# FIXME this area
BIN_OPT=""
BIN_NAME="cxxfilt"
BUG_NAMES="2016-4487 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131"
BIN_PATH=$BUILD_DIR/binutils/$BIN_NAME

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

export CC="/fuzzer/DAFL/afl-clang-fast"
export CXX="/fuzzer/DAFL/afl-clang-fast++"
export CMAKE_EXPORT_COMPILE_COMMANDS=1
export CFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"
export CXXFLAGS="$DEFAULT_FLAGS $EXTRA_FLAGS"

BIN_DIR=$SCRIPT_DIR/bin
mkdir -p $BIN_DIR

for BUG_NAME in $BUG_NAMES; do
  export DAFL_SELECTIVE_COV="$SCRIPT_DIR/DAFL-input/inst-targ/$BUG_NAME"
  export DAFL_DFG_SCORE="$SCRIPT_DIR/DAFL-input/dfg/$BUG_NAME"

  # Build
  cd $SCRIPT_DIR
  cp -rf $SRC_DIR $BUILD_DIR
  cd $BUILD_DIR && build 2>&1 | tee $SCRIPT_DIR/build_log-$BUG_NAME.txt

  # Copy
  cp $BIN_PATH $BIN_DIR/$BIN_NAME-$BUG_NAME || exit 1

  rm -rf $BUILD_DIR
done