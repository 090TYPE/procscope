#!/bin/sh
# Mount the filesystems eBPF tracepoint attach needs, then run procscope.
# Requires the container to run with --privileged (or CAP_SYS_ADMIN for the mounts).
set -e

mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true

exec /src/target/release/procscope "$@"
