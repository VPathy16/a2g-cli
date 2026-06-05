//! A2G Enforcing Gateway (ADR-0010) — binary entry point.
//!
//! Usage:
//!   a2g-gateway [--socket <path>] [--vcan <iface>] [--keys <path>]
//!
//! Defaults:
//!   --socket  /tmp/a2g-gateway.sock
//!   --vcan    vcan0
//!   --keys    /tmp/a2g-gateway-demo-keys.json
//!
//! ⚠ DEMO TIER: all keys are ephemeral (regenerated on restart).
//!   See ADR-0010 §Key provisioning for the production key management requirement.

use a2g_gateway::server::{serve, GatewayState};
use a2g_gateway::{DEFAULT_DEMO_KEY_PATH, DEFAULT_SOCKET_PATH, DEFAULT_VCAN_IFACE};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = flag_value(&args, "--socket").unwrap_or(DEFAULT_SOCKET_PATH.to_string());
    let vcan_iface = flag_value(&args, "--vcan").unwrap_or(DEFAULT_VCAN_IFACE.to_string());
    let key_path = flag_value(&args, "--keys").unwrap_or(DEFAULT_DEMO_KEY_PATH.to_string());

    eprintln!("[gateway] ⚠  DEMO TIER — ephemeral keys, not production key management");
    eprintln!("[gateway] socket  : {socket_path}");
    eprintln!("[gateway] vcan    : {vcan_iface}");
    eprintln!("[gateway] key file: {key_path}");

    let (gateway_keys, demo_keys) = a2g_gateway::keys::generate(&PathBuf::from(&key_path));
    eprintln!(
        "[gateway] receipt verifying key: {}...",
        &demo_keys.receipt_verifying_key_hex[..16]
    );

    let state = Arc::new(GatewayState::new(gateway_keys, demo_keys, &vcan_iface));

    let (_ready_tx, ready_rx) = mpsc::channel::<()>();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Graceful shutdown on Ctrl-C.
    ctrlc_simple(shutdown_tx);

    eprintln!("[gateway] listening on {socket_path}");

    let (ready_tx2, ready_rx2) = mpsc::channel::<()>();
    let socket = PathBuf::from(&socket_path);
    let state2 = Arc::clone(&state);

    let _ = ready_rx; // unused in main; just for symmetry with test helper

    serve(state2, &socket, ready_tx2, shutdown_rx);
    ready_rx2.recv().ok(); // consumed inside serve before signalling

    eprintln!("[gateway] stopped");
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn ctrlc_simple(tx: mpsc::Sender<()>) {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_sigint as *const () as libc::sighandler_t,
        );
    }

    std::thread::spawn(move || loop {
        if SIGINT_FLAG.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = tx.send(());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });
}

static SIGINT_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn handle_sigint(_: libc::c_int) {
    SIGINT_FLAG.store(true, std::sync::atomic::Ordering::Relaxed);
}
