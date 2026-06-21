//! Kernel-facing layer: load eBPF, attach tracepoints, drain the ring buffer.
//! Isolated here so the rest of the binary stays kernel-independent.

use crate::ui;
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use procscope::model::AppState;
use procscope_common::Event;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Path to the compiled eBPF object. `procscope-ebpf` is a standalone workspace,
/// so its build output lives under `procscope-ebpf/target/`, not the host target.
const BPF_OBJ: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../procscope-ebpf/target/bpfel-unknown-none/release/procscope"
);

pub async fn run(pid_filter: Option<u32>, _command: Vec<String>) -> anyhow::Result<()> {
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
                        let e: Event =
                            *bytemuck::from_bytes(&bytes[..core::mem::size_of::<Event>()]);
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
