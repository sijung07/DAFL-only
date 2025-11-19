#!/bin/bash

docker run \
    -v /mnt/c/Users/SoominK/Desktop/Dev/DAFL-only/scripts/:/scripts \
    -v /mnt/c/Users/SoominK/Desktop/Dev/DAFL-only/benchmark/:/projects \
    -v /mnt/c/Users/SoominK/Desktop/Dev/DAFL-only/results/:/results \
    --rm -it dafl /bin/bash
