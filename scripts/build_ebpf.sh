#!/bin/bash
set -e

PROBE_DIR="ebpf-programs/ssh_monitor"
TARGET_DIR="$PROBE_DIR/target/bpfel-unknown-none/release/deps"
OUT_DIR="bin"
OUT_FILE="$OUT_DIR/ssh_monitor.o"

echo "📦 Building eBPF LLVM bitcode..."

cargo +nightly rustc --release \
  --manifest-path "$PROBE_DIR/Cargo.toml" \
  --target bpfel-unknown-none -Z build-std=core \
  -- --emit=obj

echo "🔍 Searching for compiled bitcode..."
OBJ_BC=$(find "$TARGET_DIR" -maxdepth 1 -name 'ssh_monitor_ebpf-*.o' | head -n1)

if [[ -z "$OBJ_BC" ]]; then
  echo "❌ Failed: Bitcode .o not found"
  exit 1
fi

echo "🔧 Converting to ELF using llc-20..."
mkdir -p "$OUT_DIR"
llc-20 -march=bpf -filetype=obj -o "$OUT_FILE" "$OBJ_BC"

echo "✅ Done: ELF object copied to $OUT_FILE"
