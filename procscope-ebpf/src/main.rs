#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
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
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let ts = unsafe { bpf_ktime_get_ns() };
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
