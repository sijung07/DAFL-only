#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC
BUILD_DIR=$SCRIPT_DIR/BUILD

# ================================
# FIXME this area
BIN_OPT=""
BIN_NAME=""
BUG_NAMES=""
BIN_PATH=""

function build() {
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