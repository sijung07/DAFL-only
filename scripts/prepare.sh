#!/bin/bash

set -x

mkdir -p /benchmark
mkdir -p /benchmark/bin
mkdir -p /benchmark/seed
mkdir -p /benchmark/poc
cp /seed/empty /benchmark/seed/empty

BENCHMARK_BASE=/projects
TARGET=$1

SRC_BIN_DIR=$BENCHMARK_BASE/$TARGET/bin/
DST_BIN_DIR=/benchmark/bin/DAFL/$TARGET/
mkdir -p $DST_BIN_DIR
cp $SRC_BIN_DIR/* $DST_BIN_DIR/

SRC_BIN_DIR=$BENCHMARK_BASE/$TARGET/asan/
DST_BIN_DIR=/benchmark/bin/ASAN/$TARGET/
mkdir -p $DST_BIN_DIR
cp $SRC_BIN_DIR/* $DST_BIN_DIR/

SRC_SEED_DIR=$BENCHMARK_BASE/$TARGET/seed/
DST_SEED_DIR=/benchmark/seed/$TARGET/
if [[ -d $SRC_SEED_DIR ]]; then
    cp -r $SRC_SEED_DIR/ $DST_SEED_DIR/
fi

SRC_POC_DIR=$BENCHMARK_BASE/$TARGET/poc/
DST_POC_DIR=/benchmark/poc/$TARGET/
if [[ -d $SRC_POC_DIR ]]; then
    mkdir -p $DST_POC_DIR
    cp $SRC_POC_DIR/* $DST_POC_DIR/
fi
