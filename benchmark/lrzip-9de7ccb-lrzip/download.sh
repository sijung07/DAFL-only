#!/bin/bash

set -x

# FIXME below
GIT_URL="https://github.com/ckolivas/lrzip.git"
VERSION="9de7ccb"

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC

cd $SCRIPT_DIR

# FIXME: set up source code in SRC_DIR
[ ! -e $SRC_DIR ] && git clone $GIT_URL $SRC_DIR
git config --global --add safe.directory $SRC_DIR
cd $SRC_DIR
git reset --hard $VERSION