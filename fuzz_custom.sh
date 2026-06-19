#!/bin/bash
#
# Fuzz an arbitrary single-file C target with DAFL using only the source file
# and the target line.
#
# Usage:
#   ./fuzz_custom.sh <source.c> <target_line> [timelimit] [iterations]
#
# Example (the bundled simple_abort.c, target line 24, 60s, 1 run):
#   ./fuzz_custom.sh simple_abort.c 24 60 1
#
# See CUSTOM_TARGET.md for details and options.
python3 ./scripts/run_custom.py "$@"
