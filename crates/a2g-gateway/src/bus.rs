//! Vehicle bus interface — sole write path to the CAN bus (ADR-0010 §Bus Interface).
//!
//! In the demo tier this targets SocketCAN `vcan0` (virtual CAN on Linux).
//! If the interface is unavailable (CI, non-Linux, or vcan module not loaded),
//! the gateway falls back to a simulated bus that logs frames to stdout with a
//! distinctive prefix so tests can verify frame presence/absence.
//!
//! An enforced ALLOW always calls `write_enforcement_frame`.
//! A refused action never calls it — the absence of a frame is as meaningful
//! as its presence.
//!
//! ## Platform portability (ADR-0019)
//!
//! All SocketCAN code is gated `#[cfg(target_os = "linux")]`. On QNX NTO
//! (`target_os = "nto"`) and other non-Linux targets, `CanReader::open()`
//! always returns `Err` and `write_enforcement_frame` falls back to the
//! simulated bus. See `state_ingest.rs` for the QNX CAN driver skeleton and
//! `docs/qnx-integration.md` for integration notes.

use sha2::{Digest, Sha256};

/// A2G demo CAN arbitration ID (standard 11-bit, value 0x7A2).
const A2G_CAN_ID: u32 = 0x7A2;

/// Prefix used for simulated-bus log lines (checked by tests and demo scripts).
pub const SIMULATED_FRAME_PREFIX: &str = "[gateway:bus:simulated] CAN FRAME";

// ── CanReader (P1 / ADR-0016) ─────────────────────────────────────────────────

/// SocketCAN reader with configurable receive timeout.
///
/// `open()` is Linux-only. On other platforms it always returns `Err` so the
/// caller falls back gracefully; `read_frame()` is unreachable on those targets.
pub struct CanReader {
    #[cfg(target_os = "linux")]
    fd: i32,
}

impl CanReader {
    /// Open a raw CAN socket on `iface` with `SO_RCVTIMEO` set to `timeout_ms`.
    #[allow(unused_variables)]
    pub fn open(iface: &str, timeout_ms: u64) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        return can_reader_open(iface, timeout_ms);
        #[cfg(not(target_os = "linux"))]
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SocketCAN not available on this OS",
        ))
    }

    /// Read one CAN frame.
    ///
    /// Returns `Ok(Some((can_id, data)))` on success, `Ok(None)` on timeout,
    /// `Err` on unrecoverable socket error.
    pub fn read_frame(&self) -> std::io::Result<Option<(u32, [u8; 8])>> {
        #[cfg(target_os = "linux")]
        return can_reader_read(self.fd);
        #[cfg(not(target_os = "linux"))]
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
impl Drop for CanReader {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(target_os = "linux")]
fn can_reader_open(iface: &str, timeout_ms: u64) -> std::io::Result<CanReader> {
    use std::io;
    use std::mem;

    const AF_CAN: libc::c_int = 29;
    const SOCK_RAW: libc::c_int = 3;
    const CAN_RAW: libc::c_int = 1;
    const SIOCGIFINDEX: libc::c_ulong = 0x8933;
    const SOL_SOCKET: libc::c_int = 1;
    const SO_RCVTIMEO: libc::c_int = 20;

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        union_bytes: [u8; 24],
    }

    #[repr(C)]
    struct SockAddrCan {
        can_family: u16,
        can_ifindex: i32,
        _pad: [u8; 8],
    }

    unsafe {
        let fd = libc::socket(AF_CAN, SOCK_RAW, CAN_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr = IfReq {
            name: [0u8; 16],
            union_bytes: [0u8; 24],
        };
        let name_bytes = iface.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.name[..len].copy_from_slice(&name_bytes[..len]);

        if libc::ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut _) < 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }
        let ifindex = i32::from_ne_bytes(ifr.union_bytes[0..4].try_into().unwrap());

        let addr = SockAddrCan {
            can_family: AF_CAN as u16,
            can_ifindex: ifindex,
            _pad: [0u8; 8],
        };
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<SockAddrCan>() as libc::socklen_t,
        ) < 0
        {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        // Set receive timeout.
        let secs = timeout_ms / 1_000;
        let usecs = (timeout_ms % 1_000) * 1_000;
        let tv = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: usecs as libc::suseconds_t,
        };
        libc::setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        Ok(CanReader { fd })
    }
}

#[cfg(target_os = "linux")]
fn can_reader_read(fd: i32) -> std::io::Result<Option<(u32, [u8; 8])>> {
    use std::io;
    use std::mem;

    // can_frame: 4-byte ID + 1-byte DLC + 3-byte padding + 8-byte data.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CanFrame {
        can_id: u32,
        can_dlc: u8,
        _pad: [u8; 3],
        data: [u8; 8],
    }

    unsafe {
        let mut frame = CanFrame {
            can_id: 0,
            can_dlc: 0,
            _pad: [0u8; 3],
            data: [0u8; 8],
        };
        let n = libc::read(
            fd,
            &mut frame as *mut _ as *mut libc::c_void,
            mem::size_of::<CanFrame>(),
        );
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock
                || err.kind() == io::ErrorKind::TimedOut
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                return Ok(None); // timeout — no frame available
            }
            return Err(err);
        }
        if n != mem::size_of::<CanFrame>() as isize {
            return Ok(None);
        }
        Ok(Some((frame.can_id & 0x1FFF_FFFF, frame.data)))
    }
}

/// Returns `true` if the named CAN interface exists on this host.
///
/// Used by tests to decide whether to expect a real-bus write or the simulated
/// fallback.  Does not check socket permissions — a present interface may still
/// fail to write if the process lacks `CAP_NET_RAW`.
pub fn vcan_available(iface: &str) -> bool {
    #[cfg(target_os = "linux")]
    return std::path::Path::new(&format!("/sys/class/net/{iface}")).exists();
    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        false
    }
}

/// Write an enforcement CAN frame for a verified ALLOW verdict.
///
/// Returns `(frame_hex, real_write)`.  `real_write` is `true` when a real
/// SocketCAN write succeeded; `false` when the simulated fallback fired (CI,
/// no vcan kernel module, or missing `CAP_NET_RAW`).
///
/// Frame layout (ADR-0010 §Bus Interface):
/// - Bytes 0–3: bytes 4–7 of the verdict UUID (hex, dashes stripped)
/// - Bytes 4–7: first 4 bytes of SHA-256(tool)
pub fn write_enforcement_frame(iface: &str, verdict_id: &str, tool: &str) -> (String, bool) {
    let frame = build_frame(verdict_id, tool);
    let hex = hex::encode(frame);

    let wrote_real = try_write_real(iface, &frame);
    if wrote_real {
        println!("[gateway:bus] CAN FRAME {} on {}", hex, iface);
    } else {
        println!("{} {} on {}", SIMULATED_FRAME_PREFIX, hex, iface);
    }

    (hex, wrote_real)
}

fn build_frame(verdict_id: &str, tool: &str) -> [u8; 8] {
    // Verdict UUID bytes 4-7 (strip dashes first).
    let vid_clean: String = verdict_id.chars().filter(|c| *c != '-').collect();
    let vid_bytes = hex::decode(&vid_clean).unwrap_or_default();

    // First 4 bytes of SHA-256(tool).
    let tool_hash = Sha256::digest(tool.as_bytes());

    let mut frame = [0u8; 8];
    for (i, byte) in frame.iter_mut().enumerate().take(4) {
        *byte = vid_bytes.get(4 + i).copied().unwrap_or(0);
    }
    for (i, byte) in frame.iter_mut().enumerate().skip(4) {
        *byte = tool_hash[i - 4];
    }
    frame
}

/// Attempt a real SocketCAN write on Linux. Returns `true` on success.
/// Any failure (interface absent, module not loaded, permissions) returns `false`
/// and the caller falls back to the simulated bus.
#[allow(unused_variables)]
fn try_write_real(iface: &str, frame_data: &[u8; 8]) -> bool {
    #[cfg(target_os = "linux")]
    return write_socketcan(iface, frame_data).is_ok();
    #[cfg(not(target_os = "linux"))]
    false
}

#[cfg(target_os = "linux")]
fn write_socketcan(iface: &str, data: &[u8; 8]) -> std::io::Result<()> {
    use std::io;
    use std::mem;

    const AF_CAN: libc::c_int = 29;
    const SOCK_RAW: libc::c_int = 3;
    const CAN_RAW: libc::c_int = 1;
    const SIOCGIFINDEX: libc::c_ulong = 0x8933;

    // ifreq: 16-byte name + 24-byte union (we read ifindex as first i32 of union).
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        union_bytes: [u8; 24],
    }

    // sockaddr_can: 2-byte family + 4-byte ifindex + 8-byte padding.
    #[repr(C)]
    struct SockAddrCan {
        can_family: u16,
        can_ifindex: i32,
        _pad: [u8; 8],
    }

    // can_frame: 4-byte ID + 1-byte DLC + 3-byte padding + 8-byte data = 16 bytes.
    #[repr(C)]
    struct CanFrame {
        can_id: u32,
        can_dlc: u8,
        _pad: [u8; 3],
        data: [u8; 8],
    }

    unsafe {
        let fd = libc::socket(AF_CAN, SOCK_RAW, CAN_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr = IfReq {
            name: [0u8; 16],
            union_bytes: [0u8; 24],
        };
        let name_bytes = iface.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.name[..len].copy_from_slice(&name_bytes[..len]);

        if libc::ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut _) < 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        let ifindex = i32::from_ne_bytes(ifr.union_bytes[0..4].try_into().unwrap());

        let addr = SockAddrCan {
            can_family: AF_CAN as u16,
            can_ifindex: ifindex,
            _pad: [0u8; 8],
        };

        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<SockAddrCan>() as libc::socklen_t,
        ) < 0
        {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        let frame = CanFrame {
            can_id: A2G_CAN_ID,
            can_dlc: 8,
            _pad: [0u8; 3],
            data: *data,
        };

        let n = libc::write(
            fd,
            &frame as *const _ as *const libc::c_void,
            mem::size_of::<CanFrame>(),
        );
        libc::close(fd);

        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
