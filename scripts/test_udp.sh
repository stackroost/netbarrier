#!/bin/bash
set -euo pipefail

# Config
TARGET_IP="127.0.0.1"
PORT=9090
INTERFACE="wlp2s0"
PACKETS=50
DELAY=0.05
MONITOR_LOG="udp_monitor.log"

echo "[*] Using interface: $INTERFACE"

# Start Go UDP monitor in background
echo "[*] Starting eBPF UDP monitor..."
sudo go run main.go udp-monitor > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 1  # Let monitor attach

# Start a UDP listener in background
echo "[*] Starting UDP listener on $TARGET_IP:$PORT"
nc -u -l "$TARGET_IP" "$PORT" > /dev/null &
LISTENER_PID=$!
sleep 0.5

# Send test packets
echo "[*] Sending $PACKETS UDP packets to $TARGET_IP:$PORT..."
for i in $(seq 1 $PACKETS); do
  echo "Test packet $i" | nc -u -w1 "$TARGET_IP" "$PORT"
  sleep $DELAY
done
echo "[✓] UDP packet send complete."

# Wait for monitor to print updates
echo "[*] Waiting for eBPF monitor output..."
sleep 5

# Show monitor logs
echo -e "\n[+] eBPF Monitor Output:"
tail -n 30 "$MONITOR_LOG"

# Cleanup
echo "[*] Cleaning up..."
kill $MONITOR_PID >/dev/null 2>&1 || true
kill $LISTENER_PID >/dev/null 2>&1 || true

echo "[✓] Test complete."
