//! A2G Enforcing Gateway (ADR-0010) — binary entry point.
//!
//! Usage:
//!   a2g-gateway [--socket <path>] [--vcan <iface>] [--keys <path>]
//!               [--production --keystore <path>]
//!
//! Defaults:
//!   --socket  /tmp/a2g-gateway.sock
//!   --vcan    vcan0
//!   --keys    /tmp/a2g-gateway-demo-keys.json
//!
//! Modes (ADR-0015):
//!   dev (default)  — ephemeral keys regenerated on startup, loud warning.
//!   --production   — REQUIRES --keystore <path> pointing at a provisioned
//!                    keystore JSON. Refuses to start otherwise (SPEC §10.1
//!                    Level 3). No demo key file is written.

use a2g_gateway::keys::{DemoKeys, GatewayKeys};
use a2g_gateway::pending::PendingQueue;
use a2g_gateway::server::{serve, GatewayState};
use a2g_gateway::state_ingest::{spawn_reader, DEFAULT_GEAR_CAN_ID, DEFAULT_SPEED_CAN_ID};
use a2g_gateway::{DEFAULT_DEMO_KEY_PATH, DEFAULT_SOCKET_PATH, DEFAULT_VCAN_IFACE};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = flag_value(&args, "--socket").unwrap_or(DEFAULT_SOCKET_PATH.to_string());
    let vcan_iface = flag_value(&args, "--vcan").unwrap_or(DEFAULT_VCAN_IFACE.to_string());
    let key_path = flag_value(&args, "--keys").unwrap_or(DEFAULT_DEMO_KEY_PATH.to_string());
    let production = args.iter().any(|a| a == "--production");
    // --state-ingest: start the background SocketCAN reader for gateway-side state
    // verification (ADR-0016). Uses --vcan as the interface by default.
    let state_ingest = args.iter().any(|a| a == "--state-ingest");
    // --queue-persist <path>: persist the pending queue and nonce HWM to disk (P3).
    let queue_persist_path = flag_value(&args, "--queue-persist");

    let (gateway_keys, demo_keys): (GatewayKeys, DemoKeys) = if production {
        // Production mode: a provisioned keystore is mandatory. Fail-explicit —
        // there is no ephemeral-key fallback in production (SPEC §10.1 Level 3).
        let keystore_path = match flag_value(&args, "--keystore") {
            Some(p) => p,
            None => {
                eprintln!(
                    "[gateway] FATAL: --production requires --keystore <path>. \
                     Refusing to start with ephemeral keys in production mode \
                     (SPEC §10.1 Level 3; ADR-0015)."
                );
                std::process::exit(1);
            }
        };
        let keys = match a2g_gateway::keys::load_production(&PathBuf::from(&keystore_path)) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[gateway] FATAL: keystore rejected: {e}");
                eprintln!("[gateway] Refusing to start in production mode without a properly provisioned keystore.");
                std::process::exit(1);
            }
        };
        eprintln!("[gateway] production mode — keys loaded from {keystore_path}");
        let demo = DemoKeys {
            warning: "production mode — no demo private keys".to_string(),
            receipt_signing_key_hex: String::new(),
            attester_signing_key_hex: String::new(),
            operator_signing_key_hex: String::new(),
            receipt_verifying_key_hex: hex::encode(keys.receipt_verifying_key.to_bytes()),
            attester_verifying_key_hex: hex::encode(keys.attester_verifying_key.to_bytes()),
            operator_verifying_key_hex: hex::encode(keys.operator_verifying_key.to_bytes()),
            binding_verifying_key_hex: hex::encode(
                keys.binding_signing_key.verifying_key().to_bytes(),
            ),
        };
        (keys, demo)
    } else {
        eprintln!("[gateway] ⚠  DEMO TIER — ephemeral keys, not production key management");
        eprintln!("[gateway] key file: {key_path}");
        a2g_gateway::keys::generate(&PathBuf::from(&key_path))
    };

    eprintln!("[gateway] socket  : {socket_path}");
    eprintln!("[gateway] vcan    : {vcan_iface}");
    eprintln!(
        "[gateway] receipt verifying key: {}...",
        &demo_keys.receipt_verifying_key_hex[..16]
    );

    let pending = match queue_persist_path {
        Some(ref p) => {
            eprintln!("[gateway] queue persistence: {p}");
            PendingQueue::with_persist(&PathBuf::from(p))
        }
        None => PendingQueue::new(),
    };
    let state = Arc::new(GatewayState::new_with_queue(
        gateway_keys,
        demo_keys,
        &vcan_iface,
        pending,
    ));

    if state_ingest {
        let ingest = Arc::clone(&state.state_ingest);
        spawn_reader(
            ingest,
            vcan_iface.clone(),
            DEFAULT_SPEED_CAN_ID,
            DEFAULT_GEAR_CAN_ID,
        );
        eprintln!(
            "[gateway] state-ingest: subscribing to {vcan_iface} \
             (speed=0x{DEFAULT_SPEED_CAN_ID:03X} gear=0x{DEFAULT_GEAR_CAN_ID:03X})"
        );
    }

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
