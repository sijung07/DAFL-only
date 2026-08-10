#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Out-of-bounds write (CWE-787) example for DAFL.
 *
 * Input bytes:  [0] index   [1] value
 *
 * `table` holds 16 bytes and is followed by a 16-byte canary. The index byte is
 * folded into 0..31, so any value >= 16 writes past the end of `table` and into
 * the canary -- the out-of-bounds write this target demonstrates.
 *
 * The canary check is the oracle, and it is here on purpose. The fuzzing runner
 * leaves ASAN at abort_on_error=0, so ASAN reports a memory error and then exits
 * quietly with status 1, while AFL only records a crash when the target dies
 * from a signal. (ASAN also does not flag one struct field overflowing into the
 * next by default -- that needs -fsanitize-address-field-padding.) Detecting the
 * clobbered canary here and calling abort() raises SIGABRT, which AFL does
 * record, without changing the runner script shared with the benchmark runs.
 */
int main(int argc, char **argv) {
    struct {
        char table[16];
        unsigned char canary[16];
    } buf;
    int idx, val, i;
    FILE *input = stdin;

    if (argc > 1) {
        input = fopen(argv[1], "rb");
        if (input == NULL) {
            perror("fopen");
            return 1;
        }
    }

    idx = fgetc(input);
    val = fgetc(input);
    if (input != stdin) {
        fclose(input);
    }

    if (idx == EOF || val == EOF) {
        return 0;
    }

    idx = idx & 0x1F;

    memset(buf.table, 0, sizeof(buf.table));
    memset(buf.canary, 0x5A, sizeof(buf.canary));

    buf.table[idx] = (char)val;

    for (i = 0; i < (int)sizeof(buf.canary); i++) {
        if (buf.canary[i] != 0x5A) {
            fprintf(stderr, "OOB_WRITE_DETECTED at table[%d]\n", idx);
            fflush(stderr);
            abort();
        }
    }

    printf("table[%d] = %d\n", idx, (int)buf.table[idx]);
    return 0;
}
