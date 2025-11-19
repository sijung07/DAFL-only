#!/bin/bash

set -x

# FIXME below
VERSION="2.9.4"
URL="https://github.com/GNOME/libxml2/archive/refs/tags/v$VERSION.zip"
DIRNAME="libxml2-$VERSION"

SCRIPT_DIR=$(dirname $(realpath "${BASH_SOURCE[0]}"))
SRC_DIR=$SCRIPT_DIR/SRC

cd $SCRIPT_DIR

# FIXME: set up source code in SRC_DIR
wget $URL -O $SCRIPT_DIR/SRC.zip
unzip $SCRIPT_DIR/SRC.zip || exit 1
mv libxml2-$VERSION $SRC_DIR