#!/usr/bin/env bash
# Build and run procscope in Docker. Works on any OS with Docker and a
# BTF-enabled Linux kernel (native Linux, Docker Desktop on WSL2, etc.).
# Any arguments are forwarded to procscope, e.g. ./run.sh -p 1234
set -e

docker build -t procscope:dev .
exec docker run --rm -it --privileged --pid=host \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    procscope:dev "$@"
