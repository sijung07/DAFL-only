#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    FILE *input = stdin;
    int byte = EOF;

    if (argc > 1) {
        input = fopen(argv[1], "rb");
        if (input == NULL) {
            perror("fopen");
            return 1;
        }
    }

    byte = fgetc(input);
    if (input != stdin) {
        fclose(input);
    }

    if (byte == '!') {
        fprintf(stderr, "SIMPLE_ABORT_TRIGGERED\n");
        fflush(stderr);
        abort();
    }

    return 0;
}