#!/bin/bash
#
# Fuzz every bundled example target in new-targets/.
# Each entry is "<source> <target line>"; see CUSTOM_TARGET.md for the target
# line rules (it must be a statement that uses input-derived data).

TIME=${1:-60}
ITERS=${2:-1}

TARGETS=(
    "new-targets/simple_abort.c 21"   # reachable abort()      -> SIGABRT
    "new-targets/oob_write.c 53"      # out-of-bounds write    -> canary + abort()
)

for t in "${TARGETS[@]}"; do
    set -- $t
    echo ""
    echo "=============================================================="
    echo " $1  (target line $2, ${TIME}s x ${ITERS})"
    echo "=============================================================="
    ./fuzz_custom.sh "$1" "$2" "$TIME" "$ITERS"
done
