#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use procscope_common::{Event, EventKind};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// For syscall tracepoints, args begin at offset 16 (8 common bytes + 8 for the
// syscall nr). Arg N lives at 16 + 8*N.
const ARG0: usize = 16;
const ARG1: usize = 24;

#[inline(always)]
fn base(kind: EventKind) -> Event {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut e = Event::new(pid, kind, 0);
    e.ts_ns = ts;
    if let Ok(c) = bpf_get_current_comm() {
        e.comm = c;
    }
    e
}

#[inline(always)]
fn submit(e: Event) {
    if let Some(mut slot) = EVENTS.reserve::<Event>(0) {
        slot.write(e);
        slot.submit(0);
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn on_openat(ctx: TracePointContext) -> u32 {
    let mut e = base(EventKind::Open);
    if let Ok(ptr) = unsafe { ctx.read_at::<u64>(ARG1) } {
        let n = match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, &mut e.path) } {
            Ok(s) => s.len(),
            Err(_) => 0,
        };
        e.path_len = n as u32;
    }
    submit(e);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn on_connect(ctx: TracePointContext) -> u32 {
    let mut e = base(EventKind::Connect);
    if let Ok(ptr) = unsafe { ctx.read_at::<u64>(ARG1) } {
        if let Ok(buf) = unsafe { bpf_probe_read_user::<[u8; 8]>(ptr as *const [u8; 8]) } {
            let family = u16::from_ne_bytes([buf[0], buf[1]]);
            if family == 2 {
                // AF_INET: sin_port (BE) at 2, sin_addr (BE) at 4.
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64);
                e.arg = ip | ((port as u64) << 32);
            }
        }
    }
    submit(e);
    0
}

#[inline(always)]
fn fd_event(ctx: &TracePointContext, kind: EventKind) -> Event {
    let mut e = base(kind);
    if let Ok(fd) = unsafe { ctx.read_at::<u64>(ARG0) } {
        e.arg = fd;
    }
    e
}

#[tracepoint(category = "syscalls", name = "sys_enter_read")]
pub fn on_read(ctx: TracePointContext) -> u32 {
    submit(fd_event(&ctx, EventKind::Read));
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
pub fn on_write(ctx: TracePointContext) -> u32 {
    submit(fd_event(&ctx, EventKind::Write));
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_accept")]
pub fn on_accept(_ctx: TracePointContext) -> u32 {
    submit(base(EventKind::Accept));
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn on_execve(_ctx: TracePointContext) -> u32 {
    submit(base(EventKind::Exec));
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_exit_group")]
pub fn on_exit(_ctx: TracePointContext) -> u32 {
    submit(base(EventKind::Exit));
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
