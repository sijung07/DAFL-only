#!/bin/bash

set -x

apt install -y texinfo

# FIXME below
VERSION="2.31.1"
URL="http://ftp.gnu.org/gnu/binutils/binutils-$VERSION.tar.gz"
DIRNAME="binutils-$VERSION"

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC

cd $SCRIPT_DIR

# FIXME: set up source code in SRC_DIR
wget $URL -O $SCRIPT_DIR/binutils-$VERSION.tar.gz
tar -xzf $SCRIPT_DIR/binutils-$VERSION.tar.gz || exit 1
mv $SCRIPT_DIR/$DIRNAME $SRC_DIR