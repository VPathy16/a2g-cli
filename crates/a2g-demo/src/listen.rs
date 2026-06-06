//! CAN bus listener — subscribes to a SocketCAN interface and prints
//! A2G enforcement frames (CAN ID 0x7A2) as they arrive.
//!
//! Run this in a second terminal pane alongside `a2g-demo run`.
//! Frames appear here only when the gateway enforces an ALLOW action.
//! Silence during beats 2 and 3 is intentional and meaningful.
//!
//! Requires Linux with the `vcan` kernel module loaded.
//! Non-Linux: prints a one-line message and exits.

/// A2G demo CAN arbitration ID (standard 11-bit, matching the gateway).
const A2G_CAN_ID: u32 = 0x7A2;

pub fn listen(iface: &str) {
    println!(
        "[listener] Subscribing to {} for A2G frames (CAN ID 0x{A2G_CAN_ID:03X})",
        iface
    );
    println!("[listener] Frames appear here when the gateway enforces an ALLOW.");
    println!("[listener] Silence during beats 2 and 3 is intentional — the bus is quiet.");
    println!("[listener] Ready. Waiting ...");
    println!();

    listen_impl(iface);
}

// ── Linux SocketCAN implementation ────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn listen_impl(iface: &str) {
    use libc::*;
    use std::mem;

    const AF_CAN: c_int = 29;
    const SOCK_RAW: c_int = 3;
    const CAN_RAW: c_int = 1;
    const SIOCGIFINDEX: c_ulong = 0x8933;

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

    #[repr(C)]
    struct CanFrame {
        can_id: u32,
        can_dlc: u8,
        _pad: [u8; 3],
        data: [u8; 8],
    }

    unsafe {
        let fd = socket(AF_CAN, SOCK_RAW, CAN_RAW);
        if fd < 0 {
            eprintln!(
                "[listener] Failed to open AF_CAN socket: {}",
                std::io::Error::last_os_error()
            );
            eprintln!("[listener] Ensure vcan module is loaded: modprobe vcan");
            return;
        }

        let mut ifr = IfReq {
            name: [0u8; 16],
            union_bytes: [0u8; 24],
        };
        let name_bytes = iface.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.name[..len].copy_from_slice(&name_bytes[..len]);

        if ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut _) < 0 {
            close(fd);
            eprintln!(
                "[listener] Cannot find interface '{}': {}",
                iface,
                std::io::Error::last_os_error()
            );
            eprintln!("[listener] Setup: modprobe vcan && ip link add dev {iface} type vcan && ip link set up {iface}");
            return;
        }

        let ifindex = i32::from_ne_bytes(ifr.union_bytes[0..4].try_into().unwrap());
        let addr = SockAddrCan {
            can_family: AF_CAN as u16,
            can_ifindex: ifindex,
            _pad: [0u8; 8],
        };

        if bind(
            fd,
            &addr as *const _ as *const sockaddr,
            mem::size_of::<SockAddrCan>() as socklen_t,
        ) < 0
        {
            close(fd);
            eprintln!(
                "[listener] bind failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        loop {
            let mut frame = CanFrame {
                can_id: 0,
                can_dlc: 0,
                _pad: [0; 3],
                data: [0; 8],
            };
            let n = read(
                fd,
                &mut frame as *mut _ as *mut c_void,
                mem::size_of::<CanFrame>(),
            );
            if n < 0 {
                eprintln!("[listener] read error: {}", std::io::Error::last_os_error());
                break;
            }
            if n == 0 {
                continue;
            }

            // Filter for A2G frames only (CAN ID 0x7A2).
            let raw_id = frame.can_id & 0x1FFF_FFFF;
            if raw_id != A2G_CAN_ID {
                continue;
            }

            let ts = chrono::Utc::now().format("%H:%M:%S%.3f");
            let hex = hex::encode(frame.data);
            let verdict_frag = hex::encode(&frame.data[0..4]);
            let tool_hash = hex::encode(&frame.data[4..8]);
            println!(
                "\x1b[95m\x1b[1m[{ts}] A2G FRAME  hex={hex}  verdict_frag={verdict_frag}  tool_hash={tool_hash}\x1b[0m"
            );
        }

        close(fd);
    }
}

#[cfg(not(target_os = "linux"))]
fn listen_impl(iface: &str) {
    println!("[listener] Real CAN bus listener requires Linux with the vcan kernel module.");
    println!("[listener] Interface requested: {iface}");
    println!("[listener] On Linux:");
    println!("[listener]   modprobe vcan");
    println!("[listener]   ip link add dev {iface} type vcan");
    println!("[listener]   ip link set up {iface}");
}
