#!/bin/bash

set -x

# FIXME below
VERSION="2.0.4"
URL="https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/$VERSION.zip"
DIRNAME="libjpeg-turbo-$VERSION"

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC

cd $SCRIPT_DIR

# FIXME: set up source code in SRC_DIR
wget $URL -O $SCRIPT_DIR/libjpeg-turbo-$VERSION.zip
unzip $SCRIPT_DIR/libjpeg-turbo-$VERSION.zip || exit 1
mv $SCRIPT_DIR/$DIRNAME $SRC_DIR