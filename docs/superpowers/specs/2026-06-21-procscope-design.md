# procscope — Design

**Date:** 2026-06-21
**Status:** Approved, ready for implementation planning

## Summary

`procscope` is a terminal tool that shows what every process on a Linux box is
actually doing — files opened, network connections, and system-call activity —
live, using eBPF. It is the sibling of `memscope` (memory) in a "scope" family of
visual developer tools.

One-line hook: *"See what every process on your Linux box is actually doing —
files, network, syscalls — live, via eBPF."*

The selling demo: run `procscope`, then in another terminal run `curl` or
`cat /etc/passwd`. Those processes light up, showing the files they open and the
endpoints they connect to. A real-time stream of syscalls, colored by category,
makes the system look like it is "breathing."

## Goals

- Maximum discoverability / stars: eBPF + Rust + TUI is a high-virality combination.
- Real, useful tool — not a toy. Honest about dropped events and missing capabilities.
- Shippable in 1–2 weeks (MVP scope below).

## Non-Goals (v2+)

- Full argument decode for all ~300 syscalls.
- Flame graphs, recording/replay, export.
- macOS / Windows support.

## Architecture

Three crates with clean boundaries:

```
procscope-common   shared event structs, no_std (kernel <-> user)
procscope-ebpf     kernel-side eBPF programs
procscope (bin)    userspace loader + aggregation + TUI
```

`procscope-ebpf` attaches to tracepoints (`raw_syscalls/sys_enter` and
`sys_exit`) plus specific syscalls of interest (`openat`, `read`, `write`,
`connect`, `accept`, `execve`, `exit`) and emits events to userspace through a
ring buffer.

`procscope` (binary) is split into focused modules:

- `capture/` — loads the eBPF programs with `aya`, reads the ring buffer,
  produces a stream of `Event` values. Isolates everything kernel-related.
- `model/` — per-PID aggregation and syscall categorization. Pure functions over
  `Event` values; no I/O, fully unit-testable.
- `ui/` — `ratatui` rendering. A pure `render(state) -> frame` function plus
  input handling.

### Data flow

```
kernel tracepoint -> ring buffer -> capture -> Event -> model (aggregate) -> ui (render @ 10-20 fps)
```

## MVP Scope

In scope:

- Capture high-value syscalls: `openat, read, write, connect, accept, execve,
  exit`, plus a total counter of all syscalls.
- Per-PID aggregation: syscall rate, top syscalls, opened files, network endpoints.
- TUI:
  - Left: process list sorted by syscall rate, each with a sparkline.
  - Right: detail for the selected process — a live scroll of syscalls
    (`openat /etc/passwd`, `connect 1.2.3.4:443`) plus per-category counters.
  - Footer: global syscall rate and a filter input.
- Color by category: file / network / process / memory / other.
- Modes: `procscope` (all), `procscope -p PID`, `procscope -- <cmd>` (launch and
  follow).
- Single binary. Requires root or `CAP_BPF`.

Out of scope (deferred to v2): full argument decode for all syscalls, flame
graphs, record/replay, export, non-Linux platforms.

## Error Handling

- Missing `CAP_BPF` / not root → clear message: `need sudo or CAP_BPF`.
- Kernel too old / tracepoint missing → error naming the missing tracepoint.
- Ring buffer overflow → a drop counter shown directly in the UI. We never hide
  lost events.

## Testing

- Pure layer (`model`: categorization, aggregation, event decode) — unit tests
  over synthetic `Event` values. This is where the logic lives; no eBPF needed.
- Integration: a test binary performs N `openat` and M `connect` calls; assert the
  aggregator counts the same. Runs under a privileged CI runner. If eBPF is
  unavailable in CI, the pure layer is still fully covered by unit tests.

## Launch Plan (for stars)

- README with a GIF in the first screen, badges, and `cargo install` / a
  single-binary download.
- Channels: r/rust, r/linux, r/programming, and Show HN
  ("Show HN: procscope – see what every process does, live, via eBPF").
- Cross-link with `memscope` in the profile and each repo's README (the "scope"
  family).
