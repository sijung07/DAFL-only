#!/bin/bash

TARGET=$1
TIMEOUT=$2
ITERATION=$3

# Download
cd /projects/$1
if [ ! -d SRC ]; then
    ./download.sh
fi
# Analyze
if [ ! -d smake ]; then
    ./run_smake.sh
fi
if [ ! -d DAFL-input ]; then
    python3 /scripts/run_sparrow.py $TARGET thin
fi
if [ ! -d DAFL-input-naive ]; then
    python3 /scripts/run_sparrow.py $TARGET naive
fi
# Build
if [ ! -d bin ]; then
    ./build_DAFL.sh
fi
if [ ! -d asan ]; then
    ./build_ASAN.sh
fi
# Fuzz
/scripts/prepare.sh $TARGET
python3 /scripts/run.py $TARGET $TIMEOUT $ITERATION
