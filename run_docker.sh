#!/bin/bash

CUR_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SCRIPT_DIR=$CUR_DIR/scripts
BENCH_DIR=$CUR_DIR/benchmark
RESULT_DIR=$(realpath "$1")

docker run \
    -v $SCRIPT_DIR:/scripts \
    -v $BENCH_DIR:/projects \
    -v $RESULT_DIR:/results \
    --rm -it gdfuzz /bin/bash