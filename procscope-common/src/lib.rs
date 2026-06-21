#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 64;

/// One observed syscall, shared kernel <-> userspace. `repr(C)`, POD.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub kind: u32, // EventKind as u32
    pub arg: u64,  // fd, or IPv4+port packed by encode_v4, depending on kind
    pub ts_ns: u64,
    pub comm: [u8; COMM_LEN], // process name (NUL-padded)
    pub path: [u8; PATH_LEN], // openat filename (NUL-padded), len in path_len
    pub path_len: u32,
    pub _pad: u32,
}

impl Event {
    /// Construct an event with empty comm/path (kernel and tests fill the rest).
    pub fn new(pid: u32, kind: EventKind, arg: u64) -> Self {
        Event {
            pid,
            kind: kind as u32,
            arg,
            ts_ns: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
            path_len: 0,
            _pad: 0,
        }
    }

    /// Process name as text (up to the first NUL).
    pub fn comm_str(&self) -> &str {
        cstr(&self.comm)
    }

    /// openat filename as text.
    pub fn path_str(&self) -> &str {
        let n = (self.path_len as usize).min(PATH_LEN);
        core::str::from_utf8(&self.path[..n]).unwrap_or("")
    }
}

fn cstr(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    core::str::from_utf8(&b[..end]).unwrap_or("")
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
        // repr(C), fully packed: 4+4+8+8+16+64+4+4 = 112, no padding.
        assert_eq!(core::mem::size_of::<Event>(), 112);
        let e = Event::new(7, EventKind::Open, 42);
        assert_eq!(e.pid, 7);
        assert_eq!(e.kind, EventKind::Open as u32);
        assert_eq!(e.arg, 42);
    }

    #[test]
    fn comm_and_path_decode() {
        let mut e = Event::new(1, EventKind::Open, 0);
        e.comm[..4].copy_from_slice(b"bash");
        e.path[..11].copy_from_slice(b"/etc/passwd");
        e.path_len = 11;
        assert_eq!(e.comm_str(), "bash");
        assert_eq!(e.path_str(), "/etc/passwd");
    }
}
