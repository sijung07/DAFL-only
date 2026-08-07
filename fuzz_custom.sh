#!/bin/bash
#
# Fuzz an arbitrary single-file C target with DAFL using only the source file
# and the target line.
#
# Usage:
#   ./fuzz_custom.sh <source.c> <target_line> [timelimit] [iterations]
#
# Example (the bundled simple_abort.c, target line 21, 60s, 1 run):
#   ./fuzz_custom.sh new-targets/simple_abort.c 21 60 1
#
# The target line must be a statement that *uses data* (line 21 is the
# `if (byte == '!')` branch). Pointing at `abort();` on line 24 leaves the DFG
# slice empty and Sparrow fails with `empty list to list_max()`.
#
# See CUSTOM_TARGET.md for details and options.
python3 ./scripts/run_custom.py "$@"
