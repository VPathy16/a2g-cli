//! CI integration test: run all four beats with an embedded gateway and
//! assert the correct outcome for each beat.
//!
//! This test verifies showcase logic without requiring a real vcan interface.
//! The embedded gateway uses the simulated bus fallback in CI.

use std::sync::{mpsc, Arc};
use std::thread;

use a2g_gateway::keys::generate;
use a2g_gateway::protocol::GatewayResponse;
use a2g_gateway::server::{serve, GatewayState};

use tempfile::TempDir;

// ── Embedded gateway harness (mirrors e2e.rs in a2g-gateway) ─────────────────

struct GatewayHandle {
    socket_path: std::path::PathBuf,
    demo_keys: a2g_gateway::keys::DemoKeys,
    _shutdown_tx: mpsc::Sender<()>,
    _tmp: TempDir,
}

impl GatewayHandle {
    fn start() -> Self {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("gw.sock");
        let key_path = tmp.path().join("keys.json");

        let (gw_keys, demo_keys) = generate(&key_path);
        let state = Arc::new(GatewayState::new(gw_keys, demo_keys.clone(), "vcan0"));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let state_c = Arc::clone(&state);
        let sock_c = socket_path.clone();
        thread::spawn(move || serve(state_c, &sock_c, ready_tx, shutdown_rx));
        ready_rx.recv().expect("gateway ready");

        GatewayHandle {
            socket_path,
            demo_keys,
            _shutdown_tx: shutdown_tx,
            _tmp: tmp,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_four_beat_showcase() {
    let gw = GatewayHandle::start();
    let results = a2g_demo::showcase::run_with_gateway(&gw.socket_path, &gw.demo_keys, false);

    // Beat 1: comfort ALLOW → Enforced with a non-empty frame_hex.
    match &results.beat1 {
        GatewayResponse::Enforced { frame_hex, .. } => {
            assert!(!frame_hex.is_empty(), "beat 1 must produce a frame_hex");
        }
        other => panic!("beat 1 expected Enforced; got {other:?}"),
    }

    // Beat 2: state-gated DENY from core — decision string is "DENY".
    assert_eq!(
        results.beat2_core_decision, "DENY",
        "beat 2 must be DENY from core"
    );

    // Beat 3: forbidden hard-deny — gateway refuses with "forbidden" in the reason.
    match &results.beat3 {
        GatewayResponse::Refused { reason } => {
            assert!(
                reason.contains("forbidden"),
                "beat 3 reason must mention 'forbidden'; got: {reason}"
            );
        }
        other => panic!("beat 3 expected Refused; got {other:?}"),
    }

    // Beat 4: HITL Phase-2 ALLOW → Enforced with a non-empty frame_hex.
    match &results.beat4 {
        GatewayResponse::Enforced { frame_hex, .. } => {
            assert!(!frame_hex.is_empty(), "beat 4 must produce a frame_hex");
        }
        other => panic!("beat 4 expected Enforced; got {other:?}"),
    }
}
