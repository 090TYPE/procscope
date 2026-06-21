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
        EventKind::Open => {
            let p = e.path_str();
            if p.is_empty() {
                "openat".to_string()
            } else {
                format!("openat {}", p)
            }
        }
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

    #[test]
    fn formats_openat_with_path() {
        let mut e = Event::new(1, EventKind::Open, 0);
        e.path[..11].copy_from_slice(b"/etc/passwd");
        e.path_len = 11;
        assert_eq!(format_event(&e), "openat /etc/passwd");
    }

    #[test]
    fn formats_openat_without_path() {
        let e = Event::new(1, EventKind::Open, 0);
        assert_eq!(format_event(&e), "openat");
    }

    #[test]
    fn formats_read_with_fd() {
        assert_eq!(format_event(&Event::new(1, EventKind::Read, 5)), "read fd 5");
    }

    #[test]
    fn formats_connect_with_ipv4() {
        let e = Event::new(1, EventKind::Connect, encode_v4([1, 2, 3, 4], 443));
        assert_eq!(format_event(&e), "connect 1.2.3.4:443");
    }

    #[test]
    fn formats_exit() {
        assert_eq!(format_event(&Event::new(1, EventKind::Exit, 0)), "exit");
    }
}
