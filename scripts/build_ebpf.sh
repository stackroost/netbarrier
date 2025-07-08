#!/bin/bash
set -e

# -------------------------------------
# CONFIGURATION
# -------------------------------------
BASE_DIR="ebpf-programs"
OUT_DIR="bin"
TARGET="bpfel-unknown-none"
RELEASE_PATH="target/${TARGET}/release"
DEPS_PATH="$RELEASE_PATH/deps"

# -------------------------------------
# TOOL CHECKS
# -------------------------------------
command -v llc-20 >/dev/null 2>&1 || {
  echo "Error: 'llc-20' not found. Install via LLVM 12–20." >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || {
  echo "Error: 'cargo' not found in PATH." >&2
  exit 1
}

mkdir -p "$OUT_DIR"

# -------------------------------------
# MAIN LOOP
# -------------------------------------
for PROBE_DIR in "$BASE_DIR"/*; do
  [[ -d "$PROBE_DIR" && -f "$PROBE_DIR/Cargo.toml" ]] || continue

  echo "----------------------------------------"

  # Auto-detect probe (crate) name from Cargo.toml
  PROBE_NAME=$(grep '^name' "$PROBE_DIR/Cargo.toml" | head -n1 | cut -d'"' -f2)

  if [[ -z "$PROBE_NAME" ]]; then
    echo "Error: Could not detect crate name in $PROBE_DIR/Cargo.toml" >&2
    exit 1
  fi

  echo "Building eBPF probe: $PROBE_NAME"
  echo "Source path   : $PROBE_DIR"
  echo "Target output : $OUT_DIR/$PROBE_NAME.o"
  echo

  # Step 1: Build
  echo "[1/3] Building with Cargo..."
  cargo +nightly rustc --release \
    --manifest-path "$PROBE_DIR/Cargo.toml" \
    --target "$TARGET" -Z build-std=core \
    -- --emit=obj

  # Step 2: Locate compiled object
  echo "[2/3] Locating compiled bitcode object..."
  OBJ_PATH=$(find "$PROBE_DIR/$DEPS_PATH" -maxdepth 1 -name "${PROBE_NAME}_ebpf-*.o" -o -name "${PROBE_NAME}-*.o" | head -n1)

  if [[ -z "$OBJ_PATH" ]]; then
    OBJ_PATH=$(find "$PROBE_DIR/$RELEASE_PATH" -maxdepth 1 -name "${PROBE_NAME}-*.o" | head -n1)
  fi

  if [[ -z "$OBJ_PATH" ]]; then
    echo "Error: Compiled object (.o) not found for $PROBE_NAME." >&2
    echo "Searched in:" >&2
    echo "  $PROBE_DIR/$DEPS_PATH/" >&2
    echo "  $PROBE_DIR/$RELEASE_PATH/" >&2
    exit 1
  fi

  # Step 3: Convert to final ELF format
  echo "[3/3] Converting to ELF with llc-20..."
  llc-20 -march=bpf -filetype=obj -o "$OUT_DIR/$PROBE_NAME.o" "$OBJ_PATH"

  echo "Success: $OUT_DIR/$PROBE_NAME.o created."
  echo
done

echo "All eBPF probes compiled and placed in '$OUT_DIR/'"
