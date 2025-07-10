#!/bin/bash

# Description: Simulate failed SSH login attempts and verify preconditions.
# Author: Mahesh Testing Suite for NetBarrier

TARGET_USER="fakeuser"
TARGET_HOST="localhost"
WRONG_PASS="wrongpassword"
ATTEMPTS=5

echo "[INFO] Checking sshd status..."
if ! pgrep -x sshd >/dev/null; then
    echo "[ERROR] sshd is not running. Please start SSH server."
    exit 1
fi

if ! getent passwd "$TARGET_USER" >/dev/null; then
    echo "[INFO] User '$TARGET_USER' does not exist. That's expected for this test."
else
    echo "[WARN] User '$TARGET_USER' exists. Delete it or use a different non-existent user."
fi

echo "[INFO] Verifying sshd is listening on localhost (127.0.0.1:22)..."
if ! ss -tnlp | grep -q '127.0.0.1:22'; then
    echo "[WARN] sshd is not explicitly listening on 127.0.0.1. Trying localhost anyway..."
fi

echo "[INFO] Verifying PAM library path for uretprobe attachment..."
if [ ! -f /lib/x86_64-linux-gnu/libpam.so.0 ]; then
    echo "[ERROR] libpam.so.0 not found in standard location. Update your probe loader."
    exit 1
fi

echo "-------------------------------------------"
echo "[INFO] Simulating $ATTEMPTS failed SSH logins to $TARGET_USER@$TARGET_HOST"
echo "-------------------------------------------"

for i in $(seq 1 $ATTEMPTS); do
    echo "[Attempt $i] at $(date +%T)"
    logger "[SSH-TEST] Attempt $i to $TARGET_USER@$TARGET_HOST (should fail)"
    
    sshpass -p "$WRONG_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
        "$TARGET_USER@$TARGET_HOST" "exit" 2>/dev/null

    sleep 1
done

echo "[INFO] Done. Check your eBPF logs via RingBuf or /sys/kernel/debug/tracing/trace_pipe."
