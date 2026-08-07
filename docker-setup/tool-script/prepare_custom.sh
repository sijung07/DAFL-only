#!/bin/bash
#
# prepare_custom.sh — Prepare an arbitrary single-file C target for DAFL fuzzing.
#
# This script runs *inside* the gdfuzz Docker container. Given a source file and
# a target line, it performs the whole DAFL preparation pipeline:
#   1. Preprocess the source into a CIL-frontend input (.i) for Sparrow.
#   2. Run Sparrow to slice w.r.t. the target line, producing the
#      instrumentation-target list (slice_func.txt) and the data-flow-graph
#      score file (slice_dfg.txt).
#   3. Build the DAFL-instrumented binary with afl-clang-fast, feeding the two
#      Sparrow outputs through the DAFL_SELECTIVE_COV / DAFL_DFG_SCORE env vars.
#   4. Build an ASAN binary used for crash replay/triage by run_DAFL.sh.
#
# Usage:
#   prepare_custom.sh <bin_name> <source_file> <target_line> [entry_point] [extra_cflags]
#
# extra_cflags applies to the preprocessing step as well as the two builds, so
# -I/-D reach the Sparrow frontend input. See the notes at each step below.
#
# Example (target line 21 is the `if (byte == '!')` guard; line 24 is the bare
# abort() call, which has no data dependency and makes Sparrow fail):
#   prepare_custom.sh simple_abort /custom/simple_abort.c 21 main ""
#
set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <bin_name> <source_file> <target_line> [entry_point] [extra_cflags]"
    exit 1
fi

BIN_NAME=$1
SRC=$2
LINE=$3
ENTRY=${4:-main}
EXTRA_CFLAGS=${5:-}

SPARROW=/sparrow/bin/sparrow
DAFL_CC=/fuzzer/DAFL/afl-clang-fast
DEFAULT_FLAGS="-g -fno-omit-frame-pointer -Wno-error"

SRC_BASE=$(basename "$SRC")
WORK=/benchmark/custom/$BIN_NAME
OUT=$WORK/sparrow-out

echo "[*] Preparing custom target '$BIN_NAME' (line $SRC_BASE:$LINE)"

rm -rf "$WORK"
mkdir -p "$WORK"
cp "$SRC" "$WORK/$SRC_BASE"
cd "$WORK"

### 1. Preprocess source into a .i file for Sparrow's CIL frontend.
# NOTE: do NOT pass -P; the '# <line> "file"' markers are required so that
# Sparrow maps the slice location ($SRC_BASE:$LINE) back to the source.
# EXTRA_CFLAGS is passed here too: -I/-D are needed to preprocess at all, so
# withholding them would fail this step even when the build flags were given.
# A linker flag (-l...) in EXTRA_CFLAGS is merely reported as an unused argument.
echo "[*] (1/4) Preprocessing -> $BIN_NAME.i"
clang -E $EXTRA_CFLAGS "$WORK/$SRC_BASE" -o "$WORK/$BIN_NAME.i"

### 2. Slice with Sparrow w.r.t the target line.
echo "[*] (2/4) Running Sparrow static analysis"
rm -rf "$OUT"
mkdir -p "$OUT"
set +e
$SPARROW -outdir "$OUT" -frontend cil \
    -unsound_alloc \
    -unsound_const_string \
    -unsound_recursion \
    -unsound_noreturn_function \
    -unsound_skip_global_array_init 1000 \
    -skip_main_analysis \
    -cut_cyclic_call \
    -unwrap_alloc \
    -entry_point "$ENTRY" \
    -max_pre_iter 10 \
    -slice "target=$SRC_BASE:$LINE" \
    "$WORK/$BIN_NAME.i" 2>&1 | tee "$OUT/sparrow.log"
SP_RC=${PIPESTATUS[0]}
set -e

INST_TARG="$OUT/target/slice_func.txt"
DFG_SCORE="$OUT/target/slice_dfg.txt"

if [ "$SP_RC" -ne 0 ] || [ ! -f "$INST_TARG" ] || [ ! -f "$DFG_SCORE" ]; then
    echo "[!] Sparrow did not produce a data-flow slice for $SRC_BASE:$LINE."
    if grep -q "empty list to list_max" "$OUT/sparrow.log" 2>/dev/null; then
        echo "    Reason: the target line has NO data dependency, so the data-"
        echo "    flow-graph slice is empty. DAFL guides fuzzing by data"
        echo "    dependency, so the target must be a statement that USES data"
        echo "    (a variable or expression), not a bare control statement such"
        echo "    as abort()/exit() that takes no arguments."
        echo "    Tip: target the data-bearing line instead -- e.g. the guard"
        echo "         'if (byte == ...)' rather than the abort() it leads to."
    else
        echo "    Check that '$SRC_BASE:$LINE' is a statement reachable from"
        echo "    '$ENTRY'. See $OUT/sparrow.log for the full Sparrow output."
    fi
    exit 1
fi
echo "    instrumentation targets: $(wc -l < "$INST_TARG") functions"

### 3. Build DAFL-instrumented binary.
echo "[*] (3/4) Building DAFL-instrumented binary -> /benchmark/bin/DAFL/$BIN_NAME"
mkdir -p /benchmark/bin/DAFL /benchmark/bin/ASAN
# EXTRA_CFLAGS goes *after* the source: -I/-D work in either position, but a
# library flag (-lm, -lpthread) only resolves when it follows the input file.
DAFL_SELECTIVE_COV="$INST_TARG" \
DAFL_DFG_SCORE="$DFG_SCORE" \
    $DAFL_CC $DEFAULT_FLAGS -fsanitize=address \
    "$WORK/$SRC_BASE" $EXTRA_CFLAGS -o "/benchmark/bin/DAFL/$BIN_NAME"

### 4. Build ASAN binary for crash replay (used by common-postproc.sh).
echo "[*] (4/4) Building ASAN binary -> /benchmark/bin/ASAN/$BIN_NAME"
clang $DEFAULT_FLAGS -fsanitize=address \
    "$WORK/$SRC_BASE" $EXTRA_CFLAGS -o "/benchmark/bin/ASAN/$BIN_NAME"

echo "PREPARE_DONE"
