//! A2G state simulator — broadcasts E2E-protected speed + gear frames at 50 Hz.
//!
//! Usage:
//!   a2g-state-sim [--vcan <iface>] [--speed-kph <f64>] [--gear <park|reverse|neutral|drive>]
//!
//! Defaults:
//!   --vcan      vcan0
//!   --speed-kph 0.0
//!   --gear      park
//!
//! The simulator sends CAN frames at 50 Hz on the configured SocketCAN interface
//! so that `a2g-gateway --state-ingest` can subscribe and re-gate Sensitive
//! enforcement against live bus data (ADR-0016 / SPEC §6.8).
//!
//! On non-Linux targets this binary compiles but immediately prints an error and
//! exits — SocketCAN is Linux-only.

use a2g_core::vehicle::{speed_kph_to_mmps, Gear};
use a2g_gateway::state_ingest::{
    encode_gear_frame, encode_speed_frame, DEFAULT_GEAR_CAN_ID, DEFAULT_SPEED_CAN_ID,
};
use a2g_gateway::DEFAULT_VCAN_IFACE;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iface = flag_value(&args, "--vcan").unwrap_or(DEFAULT_VCAN_IFACE.to_string());

    let speed_kph: f64 = flag_value(&args, "--speed-kph")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    let gear_str = flag_value(&args, "--gear").unwrap_or_else(|| "park".to_string());
    let gear = match gear_str.to_lowercase().as_str() {
        "park" | "p" => Gear::Park,
        "reverse" | "r" => Gear::Reverse,
        "neutral" | "n" => Gear::Neutral,
        "drive" | "d" => Gear::Drive,
        other => {
            eprintln!("[state-sim] unknown gear '{}'; defaulting to Park", other);
            Gear::Park
        }
    };

    let speed_mmps = match speed_kph_to_mmps(speed_kph) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[state-sim] invalid speed: {e}; defaulting to 0 mm/s");
            0
        }
    };

    eprintln!(
        "[state-sim] iface={iface} speed={speed_kph:.1} kph ({speed_mmps} mm/s) gear={gear_str}"
    );

    run_loop(&iface, speed_mmps, gear);
}

fn run_loop(iface: &str, speed_mmps: u32, gear: Gear) {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("[state-sim] SocketCAN is Linux-only; nothing to do on this OS.");
        let _ = (iface, speed_mmps, gear);
        return;
    }

    #[cfg(target_os = "linux")]
    {
        let mut counter: u8 = 0;
        let period = std::time::Duration::from_millis(20); // 50 Hz

        loop {
            let speed_frame = encode_speed_frame(speed_mmps, counter);
            let gear_frame = encode_gear_frame(gear, counter);

            if let Err(e) = write_can_frame(iface, DEFAULT_SPEED_CAN_ID, &speed_frame) {
                eprintln!("[state-sim] write speed frame: {e}");
            }
            if let Err(e) = write_can_frame(iface, DEFAULT_GEAR_CAN_ID, &gear_frame) {
                eprintln!("[state-sim] write gear frame: {e}");
            }

            counter = (counter + 1) % 15; // COUNTER_MODULUS
            std::thread::sleep(period);
        }
    }
}

#[cfg(target_os = "linux")]
fn write_can_frame(iface: &str, can_id: u32, data: &[u8; 8]) -> std::io::Result<()> {
    use std::io;
    use std::mem;

    const AF_CAN: libc::c_int = 29;
    const SOCK_RAW: libc::c_int = 3;
    const CAN_RAW: libc::c_int = 1;
    const SIOCGIFINDEX: libc::c_ulong = 0x8933;

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
        let fd = libc::socket(AF_CAN, SOCK_RAW, CAN_RAW);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr = IfReq {
            name: [0u8; 16],
            union_bytes: [0u8; 24],
        };
        let name_bytes = iface.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

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
            can_id,
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

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}
