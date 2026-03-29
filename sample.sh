#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
python3 "$SCRIPT_DIR/scripts/run.py" lrzip-ed51e14-2018-11496 60 10
