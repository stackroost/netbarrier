#!/bin/bash
set -euo pipefail

# Config
TARGET_IP="127.0.0.1"
PORT=9090
PACKETS=50
DELAY=0.05

echo "[*] Starting UDP listener..."
nc -u -l "$TARGET_IP" "$PORT" > /dev/null &
LISTENER_PID=$!
sleep 0.5

echo "[*] Sending $PACKETS UDP packets to $TARGET_IP:$PORT"
for i in $(seq 1 $PACKETS); do
  echo "packet $i" | nc -u -w1 "$TARGET_IP" "$PORT"
  sleep $DELAY
done
echo "[✓] Packets sent."

echo "[*] Cleaning up listener..."
kill $LISTENER_PID 2>/dev/null || true
