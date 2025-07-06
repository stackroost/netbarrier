#!/usr/bin/env bash
set -euo pipefail

# Constants
ARCH="x86"
SRC_DIR="bpf"
OUT_DIR="bin"
INCLUDE_DIRS=(
  "/usr/include"
  "/usr/include/bpf"
)

echo "[*] Building eBPF programs from '$SRC_DIR/' into '$OUT_DIR/'..."
mkdir -p "$OUT_DIR"

INCLUDES=""
for dir in "${INCLUDE_DIRS[@]}"; do
  INCLUDES+=" -I $dir"
done

# Build each .c file in the bpf/ directory
for SRC_FILE in "$SRC_DIR"/*.c; do
  FILENAME=$(basename "$SRC_FILE")
  BASENAME="${FILENAME%.c}"
  OUT_FILE="$OUT_DIR/$BASENAME.o"

  echo "    → Compiling $SRC_FILE → $OUT_FILE"

  clang -target bpf \
    -D__TARGET_ARCH_${ARCH} \
    -O2 -g -Wall -Werror \
    $INCLUDES \
    -c "$SRC_FILE" -o "$OUT_FILE"
done

echo "[✓] All eBPF programs built successfully into '$OUT_DIR/'."
