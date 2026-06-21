//! Pure rendering of an `Event` to a human-readable line.

use procscope_common::{Event, EventKind};

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
        // `arg` is 0 until per-syscall argument decode lands (v2); show the bare
        // syscall name in that case rather than a misleading `fd 0`.
        EventKind::Open if e.arg == 0 => "openat".to_string(),
        EventKind::Open => format!("openat -> fd {}", e.arg),
        EventKind::Read if e.arg == 0 => "read".to_string(),
        EventKind::Read => format!("read fd {}", e.arg),
        EventKind::Write if e.arg == 0 => "write".to_string(),
        EventKind::Write => format!("write fd {}", e.arg),
        EventKind::Connect if e.arg == 0 => "connect".to_string(),
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
        let arg = encode_v4([1, 2, 3, 4], 443);
        assert_eq!(format_event(&ev(EventKind::Connect, arg)), "connect 1.2.3.4:443");
    }

    #[test]
    fn formats_exit() {
        assert_eq!(format_event(&ev(EventKind::Exit, 0)), "exit");
    }
}
