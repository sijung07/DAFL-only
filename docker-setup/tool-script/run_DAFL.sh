#!/bin/bash

FUZZER_NAME='DAFL'
. $(dirname $0)/common-setup.sh

timeout $6 /fuzzer/DAFL/afl-fuzz \
  $DICT_OPT -m none -d -i seed -o output -- ./$2-$3 $4

. $(dirname $0)/common-postproc.sh
