# Build and run procscope inside a container.
# eBPF needs a kernel with BTF; run with --privileged (or CAP_BPF + CAP_PERFMON)
# and -v /sys/kernel/btf:/sys/kernel/btf:ro on the host.
FROM rust:1-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev make pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker

WORKDIR /src
COPY . .

# Kernel-side eBPF object (standalone workspace, nightly + BPF target).
RUN cd procscope-ebpf \
    && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# Userspace binary.
RUN cargo build --release

# The eBPF object is loaded at runtime relative to the binary's manifest dir,
# so keep the source tree layout. The entrypoint mounts tracefs/debugfs (needed
# for tracepoint attach) then execs procscope, forwarding any CLI args.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
