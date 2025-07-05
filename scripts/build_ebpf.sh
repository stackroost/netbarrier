#!/usr/bin/env bash
set -e

echo "[*] Building eBPF C program..."
mkdir -p bin

clang -g -O2 -target bpf \
  -D__TARGET_ARCH_x86 \
  -Wall -Werror \
  -I /usr/include/ \
  -I /usr/include/bpf \
  -c bpf/ssh_block.c -o bin/ssh_block.o

echo "[✓] Build complete: bin/ssh_block.o"
