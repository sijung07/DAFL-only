#!/bin/bash

set -e

# Check smake
echo "[*] Check smake..."
if [ -d "./smake" ]; then
    if [ -z "$(ls -A ./smake)" ]; then
        git clone https://github.com/prosyslab/smake.git
    fi
fi
echo "[*] smake is ready."

# Build gdfuzz
echo "[*] Build gdfuzz Docker image..."
docker build -t gdfuzz -f Dockerfile .
echo "[*] Done."
