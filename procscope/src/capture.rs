//! Kernel-facing layer: load eBPF, attach tracepoints, drain the ring buffer.
//! Isolated here so the rest of the binary stays kernel-independent.

use crate::ui;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use procscope::format::format_event;
use procscope::model::AppState;
use procscope_common::Event;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Decode one ring-buffer record into an `Event`, if it is large enough.
fn decode(bytes: &[u8]) -> Option<Event> {
    if bytes.len() >= core::mem::size_of::<Event>() {
        Some(*bytemuck::from_bytes(&bytes[..core::mem::size_of::<Event>()]))
    } else {
        None
    }
}

/// Path to the compiled eBPF object. `procscope-ebpf` is a standalone workspace,
/// so its build output lives under `procscope-ebpf/target/`, not the host target.
const BPF_OBJ: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../procscope-ebpf/target/bpfel-unknown-none/release/procscope"
);

pub async fn run(pid_filter: Option<u32>, _command: Vec<String>, print: bool) -> anyhow::Result<()> {
    let bytes = std::fs::read(BPF_OBJ).map_err(|e| {
        anyhow::anyhow!("cannot read eBPF object at {BPF_OBJ} ({e}). Build the procscope-ebpf crate first.")
    })?;
    let mut bpf = Ebpf::load(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to load eBPF (need sudo or CAP_BPF?): {e}"))?;

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

    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").expect("EVENTS map"))?;

    // Plain-text mode: stream events to stdout. Useful for piping and demos.
    if print {
        loop {
            while let Some(item) = ring.next() {
                if let Some(e) = decode(&item) {
                    if pid_filter.map_or(true, |p| p == e.pid) {
                        println!("{:>7}  {}", e.pid, format_event(&e));
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // TUI mode: a reader task drains the ring buffer into shared state.
    let state = Arc::new(Mutex::new(AppState::default()));
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                while let Some(item) = ring.next() {
                    if let Some(e) = decode(&item) {
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
