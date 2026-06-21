#![no_std]

/// One observed syscall, shared kernel <-> userspace. `repr(C)`, POD.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub kind: u32, // EventKind as u32
    pub arg: u64,  // fd, encoded dest addr, or 0 depending on kind
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_is_plain_old_data() {
        // Must be safe to read straight out of the ring buffer.
        // repr(C): u32 + u32 + u64 + u64, 8-byte aligned => 24 bytes.
        assert_eq!(core::mem::size_of::<Event>(), 24);
        let e = Event { pid: 7, kind: EventKind::Open as u32, arg: 42, ts_ns: 1 };
        assert_eq!(e.pid, 7);
        assert_eq!(e.kind, EventKind::Open as u32);
    }
}
