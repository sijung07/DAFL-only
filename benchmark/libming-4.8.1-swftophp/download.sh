#!/bin/bash

set -x

# FIXME below
GIT_URL="https://github.com/libming/libming.git"
TAG_NAME="50098023446a5412efcfbd40552821a8cba983a6"

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC

cd $SCRIPT_DIR

# FIXME: set up source code in SRC_DIR
[ ! -e $SRC_DIR ] && git clone $GIT_URL $SRC_DIR
git config --global --add safe.directory $SRC_DIR
cd $SRC_DIR
git checkout $TAG_NAME