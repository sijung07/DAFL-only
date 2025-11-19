#!/bin/bash

set -x

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))

# FIXME: Add any directories or files to be cleaned here
BIN_DIR=$SCRIPT_DIR/bin
ASAN_DIR=$SCRIPT_DIR/asan
DAFL_INPUT_DIR=$SCRIPT_DIR/DAFL-input
DAFL_INPUT_NAIVE_DIR=$SCRIPT_DIR/DAFL-input-naive
SMAKE_DIR=$SCRIPT_DIR/smake
BUILD_DIR=$SCRIPT_DIR/BUILD

rm -rf $BIN_DIR $ASAN_DIR $DAFL_INPUT_DIR $DAFL_INPUT_NAIVE_DIR $SMAKE_DIR $BUILD_DIR
rm -rf $SCRIPT_DIR/build_log-*.txt $SCRIPT_DIR/libjpeg-turbo-2.0.4.zip