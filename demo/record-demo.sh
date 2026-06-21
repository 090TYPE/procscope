#!/usr/bin/env bash
# Record a procscope demo to docs/overview.gif. Runs inside the rec container.
set -e

mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true

# Fixed terminal size for a clean, consistent GIF.
stty rows 30 cols 110 2>/dev/null || true

# Background workload so the panels are lively: lots of openat + a few connects.
(
  while :; do
    cat /etc/hostname >/dev/null 2>&1
    cat /etc/hosts >/dev/null 2>&1
    cat /etc/os-release >/dev/null 2>&1
    ( exec 3<>/dev/tcp/127.0.0.1/9 ) 2>/dev/null || true
    sleep 0.03
  done
) &
GEN=$!

asciinema rec --overwrite -c "timeout 11 /src/target/release/procscope" /tmp/demo.cast || true
kill "$GEN" 2>/dev/null || true

ls -la /tmp/demo.cast
echo "--- cast head ---"
head -c 300 /tmp/demo.cast
