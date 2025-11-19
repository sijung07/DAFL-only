#!/bin/bash

TARGET=$1
TIMEOUT=$2
ITERATION=$3

cd /projects/$1
if [ ! -d SRC ]; then
    ./download.sh
fi
./run_smake.sh
python3 /scripts/run_sparrow.py $TARGET thin
python3 /scripts/run_sparrow.py $TARGET naive
./build_DAFL.sh
/scripts/prepare.sh $TARGET
python3 /scripts/run.py $TARGET $TIMEOUT $ITERATION