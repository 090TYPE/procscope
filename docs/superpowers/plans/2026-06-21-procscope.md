# procscope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `procscope`, a Linux TUI that shows what every process is doing — files, network, syscalls — live, via eBPF.

**Architecture:** A Cargo workspace of three crates. `procscope-common` holds `no_std` event structs shared between kernel and userspace. `procscope-ebpf` is the kernel-side eBPF program built with `aya-ebpf`, attaching to syscall tracepoints and pushing events to a ring buffer. `procscope` (binary) loads the eBPF with `aya`, reads the ring buffer in `capture/`, aggregates per-PID in a pure `model/` layer, and renders with `ratatui` in `ui/`. All logic that can be tested without a kernel lives in `model/` and is unit-tested; the kernel path is integration-tested under a privileged runner.

**Tech Stack:** Rust (edition 2021), `aya` + `aya-ebpf` (eBPF), `ratatui` + `crossterm` (TUI), `clap` (CLI), `anyhow` (errors).

---

## File Structure

```
procscope/
  Cargo.toml                      # workspace
  rust-toolchain.toml             # nightly for eBPF build
  procscope-common/
    Cargo.toml
    src/lib.rs                    # Event, EventKind, no_std structs (shared)
  procscope-ebpf/
    Cargo.toml
    src/main.rs                   # tracepoint programs -> ring buffer
  procscope/
    Cargo.toml
    src/main.rs                   # CLI parse, wire capture+model+ui
    src/capture.rs                # aya load, ring buffer reader -> Event stream
    src/model.rs                  # category(), AppState aggregation (PURE)
    src/format.rs                 # render an Event to a display string (PURE)
    src/ui.rs                     # ratatui render(state) + input handling
    tests/aggregation.rs          # integration: known workload -> counts
```

Responsibility split: `model.rs` and `format.rs` are pure (no I/O, no kernel) and carry every unit test. `capture.rs` isolates all `aya`/kernel code. `ui.rs` isolates `ratatui`. `main.rs` only wires them.

---

## Task 0: Workspace scaffold

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`
- Create: `procscope-common/Cargo.toml`, `procscope-common/src/lib.rs`
- Create: `procscope/Cargo.toml`, `procscope/src/main.rs`

- [ ] **Step 1: Create workspace `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["procscope-common", "procscope"]
# procscope-ebpf is built separately (different target); added in Task 7.

[workspace.package]
edition = "2021"
license = "MIT"
repository = "https://github.com/090TYPE/procscope"
```

- [ ] **Step 2: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rust-src"]
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
/target
**/*.rs.bk
*.o
```

- [ ] **Step 4: Create `procscope-common/Cargo.toml`**

```toml
[package]
name = "procscope-common"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[features]
default = []
user = []   # enables std-side helpers when built for userspace
```

- [ ] **Step 5: Create placeholder `procscope-common/src/lib.rs`**

```rust
#![no_std]

// Event types added in Task 1.
```

- [ ] **Step 6: Create `procscope/Cargo.toml`**

```toml
[package]
name = "procscope"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
procscope-common = { path = "../procscope-common", features = ["user"] }
anyhow = "1"
clap = { version = "4", features = ["derive"] }
ratatui = "0.29"
crossterm = "0.28"
aya = "0.13"
aya-log = "0.2"
tokio = { version = "1", features = ["macros", "rt", "rt-multi-thread", "signal"] }
bytemuck = "1"
```

- [ ] **Step 7: Create placeholder `procscope/src/main.rs`**

```rust
fn main() {
    println!("procscope");
}
```

- [ ] **Step 8: Verify it builds**

Run: `cargo build`
Expected: compiles, produces `procscope` binary.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: scaffold procscope cargo workspace"
```

---

## Task 1: Shared event types (`procscope-common`)

**Files:**
- Modify: `procscope-common/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to `procscope-common/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_is_plain_old_data() {
        // Must be safe to read straight out of the ring buffer.
        assert_eq!(core::mem::size_of::<Event>(), 32);
        let e = Event { pid: 7, kind: EventKind::Open as u32, arg: 42, ts_ns: 1 };
        assert_eq!(e.pid, 7);
        assert_eq!(e.kind, EventKind::Open as u32);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p procscope-common`
Expected: FAIL — `Event` / `EventKind` not defined.

- [ ] **Step 3: Write minimal implementation**

Replace the body of `procscope-common/src/lib.rs` (keep `#![no_std]`):

```rust
#![no_std]

/// One observed syscall, shared kernel <-> userspace. `repr(C)`, POD.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub kind: u32, // EventKind as u32
    pub arg: u64,  // fd, dest addr, or 0 depending on kind
    pub ts_ns: u64,
}

/// Category of the captured syscall.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Open = 0,
    Read = 1,
    Write = 2,
    Connect = 3,
    Accept = 4,
    Exec = 5,
    Exit = 6,
    Other = 7,
}

#[cfg(feature = "user")]
unsafe impl bytemuck::Zeroable for Event {}
#[cfg(feature = "user")]
unsafe impl bytemuck::Pod for Event {}
```

Add to `procscope-common/Cargo.toml` under `[dependencies]`:

```toml
[dependencies]
bytemuck = { version = "1", optional = true }

[features]
default = []
user = ["dep:bytemuck"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope-common --features user`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(common): shared Event and EventKind types"
```

---

## Task 2: Syscall categorization (`model.rs`, pure)

**Files:**
- Create: `procscope/src/model.rs`
- Modify: `procscope/src/main.rs` (add `mod model;`)

- [ ] **Step 1: Write the failing test**

Create `procscope/src/model.rs`:

```rust
use procscope_common::EventKind;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_map_correctly() {
        assert_eq!(category(EventKind::Open), Category::File);
        assert_eq!(category(EventKind::Read), Category::File);
        assert_eq!(category(EventKind::Write), Category::File);
        assert_eq!(category(EventKind::Connect), Category::Network);
        assert_eq!(category(EventKind::Accept), Category::Network);
        assert_eq!(category(EventKind::Exec), Category::Process);
        assert_eq!(category(EventKind::Exit), Category::Process);
        assert_eq!(category(EventKind::Other), Category::Other);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Add `mod model;` to the top of `procscope/src/main.rs`, then:

Run: `cargo test -p procscope model::`
Expected: FAIL — `category` / `Category` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to the top of `procscope/src/model.rs` (above the test module):

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    File,
    Network,
    Process,
    Other,
}

pub fn category(kind: EventKind) -> Category {
    match kind {
        EventKind::Open | EventKind::Read | EventKind::Write => Category::File,
        EventKind::Connect | EventKind::Accept => Category::Network,
        EventKind::Exec | EventKind::Exit => Category::Process,
        EventKind::Other => Category::Other,
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope model::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(model): syscall categorization"
```

---

## Task 3: Per-PID aggregation (`model.rs`, pure)

**Files:**
- Modify: `procscope/src/model.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `procscope/src/model.rs`:

```rust
    use procscope_common::Event;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { pid, kind: kind as u32, arg: 0, ts_ns: 0 }
    }

    #[test]
    fn aggregates_counts_per_pid() {
        let mut state = AppState::default();
        state.ingest(ev(10, EventKind::Open));
        state.ingest(ev(10, EventKind::Open));
        state.ingest(ev(10, EventKind::Connect));
        state.ingest(ev(20, EventKind::Write));

        let p10 = state.process(10).expect("pid 10 tracked");
        assert_eq!(p10.total, 3);
        assert_eq!(p10.by_category[Category::File as usize], 2);
        assert_eq!(p10.by_category[Category::Network as usize], 1);

        let p20 = state.process(20).expect("pid 20 tracked");
        assert_eq!(p20.total, 1);
    }

    #[test]
    fn processes_sorted_by_rate_desc() {
        let mut state = AppState::default();
        state.ingest(ev(1, EventKind::Open));
        state.ingest(ev(2, EventKind::Open));
        state.ingest(ev(2, EventKind::Open));
        let order: Vec<u32> = state.processes_by_activity().iter().map(|p| p.pid).collect();
        assert_eq!(order, vec![2, 1]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p procscope model::`
Expected: FAIL — `AppState` / `Process` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `procscope/src/model.rs` (above the test module). `Category` has 4 variants:

```rust
use procscope_common::Event;
use std::collections::HashMap;

const N_CATEGORIES: usize = 4;

#[derive(Clone, Debug, Default)]
pub struct Process {
    pub pid: u32,
    pub total: u64,
    pub by_category: [u64; N_CATEGORIES],
}

#[derive(Default)]
pub struct AppState {
    procs: HashMap<u32, Process>,
}

impl AppState {
    pub fn ingest(&mut self, e: Event) {
        let kind = kind_from_u32(e.kind);
        let entry = self.procs.entry(e.pid).or_insert_with(|| Process {
            pid: e.pid,
            ..Default::default()
        });
        entry.total += 1;
        entry.by_category[category(kind) as usize] += 1;
    }

    pub fn process(&self, pid: u32) -> Option<&Process> {
        self.procs.get(&pid)
    }

    pub fn processes_by_activity(&self) -> Vec<&Process> {
        let mut v: Vec<&Process> = self.procs.values().collect();
        v.sort_by(|a, b| b.total.cmp(&a.total).then(a.pid.cmp(&b.pid)));
        v
    }
}

fn kind_from_u32(v: u32) -> EventKind {
    match v {
        0 => EventKind::Open,
        1 => EventKind::Read,
        2 => EventKind::Write,
        3 => EventKind::Connect,
        4 => EventKind::Accept,
        5 => EventKind::Exec,
        6 => EventKind::Exit,
        _ => EventKind::Other,
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope model::`
Expected: PASS (all model tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(model): per-PID aggregation and activity sorting"
```

---

## Task 4: Event formatting (`format.rs`, pure)

**Files:**
- Create: `procscope/src/format.rs`
- Modify: `procscope/src/main.rs` (add `mod format;`)

- [ ] **Step 1: Write the failing test**

Create `procscope/src/format.rs`:

```rust
use procscope_common::{Event, EventKind};

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind, arg: u64) -> Event {
        Event { pid: 1, kind: kind as u32, arg, ts_ns: 0 }
    }

    #[test]
    fn formats_open_with_fd() {
        assert_eq!(format_event(&ev(EventKind::Open, 5)), "openat -> fd 5");
    }

    #[test]
    fn formats_connect_with_ipv4() {
        // arg encodes IPv4 in network order in the low 32 bits + port in next 16.
        // 1.2.3.4:443 -> octets then port.
        let arg = encode_v4([1, 2, 3, 4], 443);
        assert_eq!(format_event(&ev(EventKind::Connect, arg)), "connect 1.2.3.4:443");
    }

    #[test]
    fn formats_exit() {
        assert_eq!(format_event(&ev(EventKind::Exit, 0)), "exit");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Add `mod format;` to `procscope/src/main.rs`, then:

Run: `cargo test -p procscope format::`
Expected: FAIL — `format_event` / `encode_v4` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to the top of `procscope/src/format.rs`:

```rust
/// Pack an IPv4 address + port into the `Event.arg` u64.
/// Bits 0..32 = octets (a<<24 | b<<16 | c<<8 | d), bits 32..48 = port.
pub fn encode_v4(octets: [u8; 4], port: u16) -> u64 {
    let ip = (octets[0] as u64) << 24
        | (octets[1] as u64) << 16
        | (octets[2] as u64) << 8
        | (octets[3] as u64);
    ip | ((port as u64) << 32)
}

pub fn format_event(e: &Event) -> String {
    let kind = match e.kind {
        0 => EventKind::Open,
        1 => EventKind::Read,
        2 => EventKind::Write,
        3 => EventKind::Connect,
        4 => EventKind::Accept,
        5 => EventKind::Exec,
        6 => EventKind::Exit,
        _ => EventKind::Other,
    };
    match kind {
        EventKind::Open => format!("openat -> fd {}", e.arg),
        EventKind::Read => format!("read fd {}", e.arg),
        EventKind::Write => format!("write fd {}", e.arg),
        EventKind::Connect => {
            let ip = e.arg & 0xFFFF_FFFF;
            let port = (e.arg >> 32) & 0xFFFF;
            format!(
                "connect {}.{}.{}.{}:{}",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF,
                port
            )
        }
        EventKind::Accept => "accept".to_string(),
        EventKind::Exec => "execve".to_string(),
        EventKind::Exit => "exit".to_string(),
        EventKind::Other => "syscall".to_string(),
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope format::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(format): human-readable event rendering"
```

---

## Task 5: Recent-event ring + UI state (`model.rs`, pure)

**Files:**
- Modify: `procscope/src/model.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `procscope/src/model.rs`:

```rust
    #[test]
    fn keeps_bounded_recent_events_per_selected_pid() {
        let mut state = AppState::default();
        for i in 0..150u64 {
            state.ingest(Event { pid: 5, kind: EventKind::Open as u32, arg: i, ts_ns: i });
        }
        let recent = state.recent_for(5);
        assert_eq!(recent.len(), 100, "ring capped at 100");
        assert_eq!(recent.last().unwrap().arg, 149, "newest kept");
        assert_eq!(recent.first().unwrap().arg, 50, "oldest dropped");
    }

    #[test]
    fn counts_dropped_events() {
        let mut state = AppState::default();
        state.note_dropped(7);
        state.note_dropped(3);
        assert_eq!(state.dropped(), 10);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p procscope model::`
Expected: FAIL — `recent_for` / `note_dropped` / `dropped` not defined.

- [ ] **Step 3: Write minimal implementation**

In `procscope/src/model.rs`, change the imports and `Process`/`AppState` to add a bounded recent ring and a drop counter. Replace the `use std::collections::HashMap;` line with:

```rust
use std::collections::{HashMap, VecDeque};

const RECENT_CAP: usize = 100;
```

Add a `recent: VecDeque<Event>` field to `Process`:

```rust
#[derive(Clone, Debug, Default)]
pub struct Process {
    pub pid: u32,
    pub total: u64,
    pub by_category: [u64; N_CATEGORIES],
    pub recent: VecDeque<Event>,
}
```

Add a `dropped: u64` field to `AppState`:

```rust
#[derive(Default)]
pub struct AppState {
    procs: HashMap<u32, Process>,
    dropped: u64,
}
```

In `ingest`, after updating counts, push to the ring:

```rust
        entry.recent.push_back(e);
        if entry.recent.len() > RECENT_CAP {
            entry.recent.pop_front();
        }
```

Add these methods to `impl AppState`:

```rust
    pub fn recent_for(&self, pid: u32) -> Vec<Event> {
        self.procs
            .get(&pid)
            .map(|p| p.recent.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn note_dropped(&mut self, n: u64) {
        self.dropped += n;
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope`
Expected: PASS (all model tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(model): bounded recent-event ring and drop counter"
```

---

## Task 6: CLI surface (`main.rs`)

**Files:**
- Modify: `procscope/src/main.rs`

- [ ] **Step 1: Write the failing test**

Create `procscope/tests/cli.rs`:

```rust
use std::process::Command;

#[test]
fn shows_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_procscope"))
        .arg("--help")
        .output()
        .expect("run procscope --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--pid"), "help mentions --pid");
    assert!(text.contains("procscope"), "help mentions binary name");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p procscope --test cli`
Expected: FAIL — no `--pid` flag yet.

- [ ] **Step 3: Write minimal implementation**

Replace `procscope/src/main.rs` with (keep the `mod` lines at top):

```rust
mod capture;
mod format;
mod model;
mod ui;

use clap::Parser;

/// Watch what processes do — files, network, syscalls — live, via eBPF.
#[derive(Parser, Debug)]
#[command(name = "procscope", version, about)]
struct Cli {
    /// Only watch this PID.
    #[arg(short, long)]
    pid: Option<u32>,

    /// Launch this command and watch it (everything after `--`).
    #[arg(last = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    capture::run(cli.pid, cli.command).await
}
```

Create a stub `procscope/src/capture.rs` so it compiles (real body in Task 8):

```rust
pub async fn run(_pid: Option<u32>, _command: Vec<String>) -> anyhow::Result<()> {
    anyhow::bail!("capture not implemented yet");
}
```

Create a stub `procscope/src/ui.rs`:

```rust
// ratatui rendering added in Task 9.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope --test cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(cli): argument parsing for pid and command modes"
```

---

## Task 7: eBPF kernel program (`procscope-ebpf`)

This crate builds for the BPF target and cannot be unit-tested on the host; it is
exercised by the Task 10 integration test. Provide complete code.

**Files:**
- Create: `procscope-ebpf/Cargo.toml`, `procscope-ebpf/src/main.rs`, `procscope-ebpf/rust-toolchain.toml`

- [ ] **Step 1: Create `procscope-ebpf/rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

- [ ] **Step 2: Create `procscope-ebpf/Cargo.toml`**

```toml
[package]
name = "procscope-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1"
procscope-common = { path = "../procscope-common" }

[[bin]]
name = "procscope"
path = "src/main.rs"

[profile.dev]
opt-level = 3
[profile.release]
lto = true
panic = "abort"
```

- [ ] **Step 3: Create `procscope-ebpf/src/main.rs`**

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use procscope_common::{Event, EventKind};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn emit(kind: EventKind, arg: u64) {
    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
        let ts = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        slot.write(Event { pid, kind: kind as u32, arg, ts_ns: ts });
        slot.submit(0);
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn on_openat(_ctx: TracePointContext) -> u32 {
    emit(EventKind::Open, 0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn on_connect(_ctx: TracePointContext) -> u32 {
    emit(EventKind::Connect, 0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn on_execve(_ctx: TracePointContext) -> u32 {
    emit(EventKind::Exec, 0);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_exit_group")]
pub fn on_exit(_ctx: TracePointContext) -> u32 {
    emit(EventKind::Exit, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 4: Build the eBPF object**

Run: `cargo +nightly build -p procscope-ebpf --target bpfel-unknown-none -Z build-std=core --release`
Expected: produces `target/bpfel-unknown-none/release/procscope` (the BPF object). If `bpf-linker` is missing, install with `cargo install bpf-linker` and retry.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ebpf): tracepoint programs emitting events to ring buffer"
```

---

## Task 8: Userspace capture (`capture.rs`)

**Files:**
- Modify: `procscope/src/capture.rs`
- Modify: `procscope/Cargo.toml` (add build embed of the BPF object)

- [ ] **Step 1: Embed the BPF object and write the loader**

Replace `procscope/src/capture.rs` with:

```rust
use crate::model::AppState;
use crate::ui;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use procscope_common::Event;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Path to the compiled eBPF object (built in Task 7).
const BPF_OBJ: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../target/bpfel-unknown-none/release/procscope");

pub async fn run(pid_filter: Option<u32>, _command: Vec<String>) -> anyhow::Result<()> {
    let bytes = std::fs::read(BPF_OBJ).map_err(|e| {
        anyhow::anyhow!("cannot read eBPF object at {BPF_OBJ} ({e}). Build Task 7 first.")
    })?;
    let mut bpf = Ebpf::load(&bytes).map_err(|e| {
        anyhow::anyhow!("failed to load eBPF (need sudo or CAP_BPF?): {e}")
    })?;

    for (prog_name, tp) in [
        ("on_openat", "sys_enter_openat"),
        ("on_connect", "sys_enter_connect"),
        ("on_execve", "sys_enter_execve"),
        ("on_exit", "sys_enter_exit_group"),
    ] {
        let program: &mut TracePoint = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("eBPF program {prog_name} missing"))?
            .try_into()?;
        program.load()?;
        program
            .attach("syscalls", tp)
            .map_err(|e| anyhow::anyhow!("attach tracepoint {tp} failed: {e}"))?;
    }

    let state = Arc::new(Mutex::new(AppState::default()));
    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").expect("EVENTS map"))?;

    // Reader loop: drain the ring buffer into AppState.
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= core::mem::size_of::<Event>() {
                        let e: Event = *bytemuck::from_bytes(&bytes[..core::mem::size_of::<Event>()]);
                        if pid_filter.map_or(true, |p| p == e.pid) {
                            state.lock().unwrap().ingest(e);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
    }

    ui::run(state).await
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p procscope`
Expected: compiles (it will fail at runtime until `ui::run` exists — added in Task 9).

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "feat(capture): load eBPF, attach tracepoints, drain ring buffer"
```

---

## Task 9: TUI rendering (`ui.rs`)

**Files:**
- Modify: `procscope/src/ui.rs`

- [ ] **Step 1: Write the failing test for the pure layout helper**

Add to `procscope/src/ui.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_row_renders_pid_and_total() {
        let row = process_row(&crate::model::Process {
            pid: 1234,
            total: 99,
            ..Default::default()
        });
        assert!(row.contains("1234"));
        assert!(row.contains("99"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p procscope ui::`
Expected: FAIL — `process_row` not defined.

- [ ] **Step 3: Write the rendering layer**

Replace `procscope/src/ui.rs` with:

```rust
use crate::format::format_event;
use crate::model::{AppState, Process};
use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Pure: one process list row. Tested.
pub fn process_row(p: &Process) -> String {
    format!("{:>7}  {:>8} syscalls", p.pid, p.total)
}

pub async fn run(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let mut selected: usize = 0;

    let res = loop {
        term.draw(|f| draw(f, &state, selected))?;

        if event::poll(Duration::from_millis(100))? {
            if let CEvent::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                    KeyCode::Down => selected = selected.saturating_add(1),
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    res
}

fn draw(f: &mut Frame, state: &Arc<Mutex<AppState>>, selected: usize) {
    let st = state.lock().unwrap();
    let procs = st.processes_by_activity();
    let sel = selected.min(procs.len().saturating_sub(1));

    let cols = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(f.area());

    let items: Vec<ListItem> = procs
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let style = if i == sel {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(process_row(p)).style(style)
        })
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("Processes")),
        cols[0],
    );

    let detail = if let Some(p) = procs.get(sel) {
        let lines: Vec<Line> = st
            .recent_for(p.pid)
            .iter()
            .rev()
            .take(40)
            .map(|e| Line::from(format_event(e)))
            .collect();
        Text::from(lines)
    } else {
        Text::from("no process selected")
    };
    let title = format!("Activity  (dropped: {})", st.dropped());
    f.render_widget(
        Paragraph::new(detail).block(Block::default().borders(Borders::ALL).title(title)),
        cols[1],
    );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p procscope ui::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): ratatui process list and live activity panel"
```

---

## Task 10: Integration test (known workload)

**Files:**
- Create: `procscope/tests/aggregation.rs`

This test exercises the pure aggregation pipeline end-to-end with synthetic
events (kernel-independent, runs anywhere). A separate live eBPF smoke test is
documented for manual/privileged-CI runs.

- [ ] **Step 1: Write the test**

Create `procscope/tests/aggregation.rs`:

```rust
use procscope::model::AppState;
use procscope_common::{Event, EventKind};

fn ev(pid: u32, kind: EventKind) -> Event {
    Event { pid, kind: kind as u32, arg: 0, ts_ns: 0 }
}

#[test]
fn known_workload_produces_expected_counts() {
    let mut state = AppState::default();
    // Simulate a process that opens 3 files and makes 2 connections.
    for _ in 0..3 {
        state.ingest(ev(4242, EventKind::Open));
    }
    for _ in 0..2 {
        state.ingest(ev(4242, EventKind::Connect));
    }
    let p = state.process(4242).expect("tracked");
    assert_eq!(p.total, 5);
    assert_eq!(p.by_category[procscope::model::Category::File as usize], 3);
    assert_eq!(p.by_category[procscope::model::Category::Network as usize], 2);
}
```

- [ ] **Step 2: Expose the crate's modules to integration tests**

Create `procscope/src/lib.rs` so integration tests can import `procscope::model`:

```rust
pub mod format;
pub mod model;
```

And add to `procscope/Cargo.toml`:

```toml
[lib]
name = "procscope"
path = "src/lib.rs"

[[bin]]
name = "procscope"
path = "src/main.rs"
```

In `procscope/src/main.rs`, replace `mod format;` and `mod model;` with `use procscope::{format, model};` (keep `mod capture;` and `mod ui;`). Update `capture.rs`/`ui.rs` imports from `crate::model` to `procscope::model` and `crate::format` to `procscope::format`.

- [ ] **Step 3: Run the test**

Run: `cargo test -p procscope --test aggregation`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: integration test for aggregation pipeline"
```

---

## Task 11: README, CI, license

**Files:**
- Create: `README.md`, `LICENSE`, `.github/workflows/ci.yml`, `docs/.gitkeep`

- [ ] **Step 1: Create `LICENSE`** (MIT, holder "090TYPE", year 2026).

- [ ] **Step 2: Create `README.md`**

```markdown
<h1 align="center">procscope</h1>
<p align="center"><b>See what every process on your Linux box is actually doing — files, network, syscalls — live, via eBPF.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/eBPF-aya-orange" alt="aya">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
</p>

<p align="center"><img src="docs/overview.gif" width="100%" alt="procscope live"></p>

## Why

`strace` shows one process as a wall of text. `htop` shows CPU and memory but not
*what* a process does. procscope shows every process's file, network and syscall
activity live, in a TUI, using low-overhead eBPF.

Sibling project: [memscope](https://github.com/090TYPE/memscope) (live C++ heap).

## Quick start

```bash
cargo install bpf-linker
cargo +nightly build -p procscope-ebpf --target bpfel-unknown-none -Z build-std=core --release
cargo build --release
sudo ./target/release/procscope            # watch everything
sudo ./target/release/procscope -p 1234    # one PID
```

Requires Linux with eBPF and `CAP_BPF` (or root).
```

- [ ] **Step 3: Create `.github/workflows/ci.yml`**

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test -p procscope-common --features user
      - run: cargo test -p procscope --lib --test aggregation --test cli
```

CI tests the host-side crates (pure model, format, CLI). The eBPF build and live
capture are verified locally / on a privileged runner.

- [ ] **Step 4: Verify CI commands pass locally**

Run: `cargo test -p procscope-common --features user && cargo test -p procscope --lib --test aggregation --test cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: README, MIT license, CI for host-side crates"
```

---

## Self-Review Notes

**Spec coverage:** capture (Tasks 7-8), per-PID aggregation (Task 3), categorization (Task 2), TUI list/detail/footer (Task 9), modes `-p`/`--`/all (Tasks 6, 8), color by category (Task 9 styling), error handling for CAP_BPF/missing tracepoint/drops (Tasks 8, 5/9), pure-layer unit tests + integration (Tasks 2-5, 10), README+launch (Task 11). The `--  <cmd>` launch mode is parsed in Task 6 and threaded through `capture::run` (the `_command` arg); spawning the child is a thin addition in Task 8's loader and is noted there.

**Deferred from MVP (matches spec non-goals):** read/write per-fd path resolution and full arg decode are represented minimally (fd numbers, encoded IPv4); richer decode is v2.

**Type consistency:** `Event{pid,kind,arg,ts_ns}`, `EventKind` (8 variants), `Category` (4 variants), `AppState::{ingest, process, processes_by_activity, recent_for, note_dropped, dropped}`, `Process{pid,total,by_category,recent}`, `format_event`, `encode_v4`, `process_row` — names used consistently across tasks.
