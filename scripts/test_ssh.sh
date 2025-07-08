#!/bin/bash

TARGET="127.0.0.1"
PORT=22
ATTEMPTS=10

echo "[*] Running $ATTEMPTS SSH connection attempts to $TARGET:$PORT..."

for i in $(seq 1 $ATTEMPTS); do
  ssh -o ConnectTimeout=1 -o BatchMode=yes -o StrictHostKeyChecking=no $TARGET -p $PORT exit
  echo "Attempt $i done"
done

echo "[✓] SSH test attempts completed."
