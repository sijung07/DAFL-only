#!/bin/bash

SCRIPT_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
python3 "$SCRIPT_DIR/scripts/run.py" "eval" 86400 32
