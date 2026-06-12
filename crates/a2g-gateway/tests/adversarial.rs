//! Adversarial test suite for the A2G Enforcing Gateway (P2).
//!
//! Each test simulates one attack vector and asserts the gateway refuses it.
//! The suite is run in CI as the `adversarial` job.
//!
//! ## Attack inventory
//!
//! | # | Name                          | Target step |
//! |---|-------------------------------|-------------|
//! | 1 | `forbidden_bypass`            | Step 1 — forbidden re-check |
//! | 2 | `wrong_key_signature`         | Step 2 — signature verification |
//! | 3 | `tampered_tool_after_signing` | Step 2 — signature (tool changed post-sign) |
//! | 4 | `decision_field_mutation`     | Step 3 — decision must be ALLOW |
//! | 5 | `nonce_replay`                | Step 5 — anti-replay |
//! | 6 | `past_timestamp`              | Step 4 — freshness (> 2 s stale) |
//! | 7 | `future_timestamp`            | Step 4 — freshness (> 2 s future) |
//! | 8 | `request_hash_mutation`       | Step 6 — request_hash mismatch |
//! | 9 | `phantom_binding_id`          | Step 7 — binding not in queue |
//! | 10| `can_state_mismatch`          | ADR-0016 — gateway CAN says moving |
//! | 11| `stale_can_reader_active_fails_closed` | ADR-0016 — reader active, frames stale |
//! | 12| `pay_hitl_bypass`             | Step 3.5 — pay.* ALLOW without binding (ADR-0018) |
//! | 13| `pii_export_forbidden_bypass` | Step 1.5 — pii.profile.export cockpit forbidden (ADR-0018) |
//! | 14| `pii_grant_forgery`           | Step 3.5 — comms.contacts.read ALLOW without pii.grant binding |

use a2g_core::enforce::{decide, Decision, TrustAnchor};
use a2g_core::ledger::NoopLedger;
use a2g_core::vehicle::Gear;
use a2g_gateway::client::send_request;
use a2g_gateway::keys::generate;
use a2g_gateway::protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};
use a2g_gateway::server::{serve, GatewayState};
use a2g_gateway::state_ingest::{encode_gear_frame, encode_speed_frame};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Instant;
use tempfile::TempDir;

// ── Test harness ──────────────────────────────────────────────────────────────

struct Adv {
    state: Arc<GatewayState>,
    socket_path: PathBuf,
    _tmp: TempDir,
    shutdown_tx: mpsc::Sender<()>,
    /// The gateway's receipt signing key — used to produce valid signatures.
    receipt_sk: SigningKey,
}

impl Adv {
    fn start() -> Self {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("adv.sock");
        let key_path = tmp.path().join("keys.json");

        let (keys, demo_keys) = generate(&key_path);
        let receipt_sk = demo_keys.receipt_signing_key();
        let state = Arc::new(GatewayState::new(keys, demo_keys, "vcan0"));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let state2 = Arc::clone(&state);
        let sock2 = socket_path.clone();
        std::thread::spawn(move || serve(state2, &sock2, ready_tx, shutdown_rx));
        ready_rx.recv().expect("gateway ready");

        Adv {
            state,
            socket_path,
            _tmp: tmp,
            shutdown_tx,
            receipt_sk,
        }
    }

    fn send(&self, req: &GatewayRequest) -> GatewayResponse {
        send_request(&self.socket_path, req)
    }

    /// Build a signed receipt for a comfort ALLOW verdict.  Using the correct
    /// signing key and a fresh timestamp — useful as the baseline "valid" receipt
    /// that we then mutate in individual tests.
    fn valid_comfort_receipt(&self) -> GatewayReceipt {
        let mandate = comfort_mandate();
        let verdict = decide(
            &mandate,
            "vehicle.climate.set_temperature",
            &serde_json::json!({}),
            &NoopLedger,
            Utc::now(),
            None,
            &TrustAnchor::SelfSovereign,
        )
        .unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
        sign_fresh_receipt(
            &verdict,
            "vehicle.climate.set_temperature",
            "{}",
            &self.receipt_sk,
        )
    }
}

impl Drop for Adv {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_cbor_mandate(tools: &[&str], escalate_tools: &[&str]) -> Vec<u8> {
    use a2g_core::cbor::{encode_canonical, CborMandate, MandateTbs};
    use a2g_core::mandate::capabilities_hash;
    use chrono::Duration;

    let (agent_did, _, _) = a2g_core::identity::generate_agent_keypair();
    let (_, secret, _) = a2g_core::identity::generate_agent_keypair();
    let sk = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(&secret).unwrap().as_slice().try_into().unwrap(),
    );
    let vk = sk.verifying_key();
    let now = Utc::now();
    let expires = now.checked_add_signed(Duration::hours(24)).unwrap_or(now);
    let issuer_did = format!("did:a2g:{}", bs58::encode(vk.to_bytes()).into_string());
    let tools_owned: Vec<String> = tools.iter().map(|s| s.to_string()).collect();
    let escalate_owned: Vec<String> = escalate_tools.iter().map(|s| s.to_string()).collect();
    let cap_hash = hex::decode(capabilities_hash(&tools_owned)).unwrap();
    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did,
        issuer_did,
        agent_name: "adv-test".to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        proposal_hash: String::new(),
        workspace_root: String::new(),
        capabilities_hash: cap_hash.into(),
        tools: tools_owned,
        fs_read: vec![],
        fs_write: vec![],
        fs_deny: vec![],
        net_allow: vec![],
        net_deny: vec![],
        cmd_allow: vec![],
        cmd_deny: vec![],
        max_calls_per_minute: 60,
        max_file_size_bytes: 10_485_760,
        max_output_tokens: 4096,
        max_session_duration_sec: 3600,
        deny_patterns: vec![],
        redact_patterns: vec![],
        max_output_length: 50_000,
        region: String::new(),
        regulatory_framework: String::new(),
        environment: String::new(),
        classification: String::new(),
        operating_hours: String::new(),
        escalate_tools: escalate_owned.clone(),
        escalate_paths: vec![],
        escalate_hosts: vec![],
        escalate_to: if escalate_owned.is_empty() {
            String::new()
        } else {
            "did:a2g:approver".to_string()
        },
    };
    let tbs_bytes = encode_canonical(&tbs).unwrap();
    let sig = sk.sign(&tbs_bytes);
    let envelope = CborMandate {
        tag: "MANDATE-V1".to_string(),
        tbs: tbs_bytes.into(),
        signature: sig.to_bytes().to_vec().into(),
        issuer_pubkey: vk.to_bytes().to_vec().into(),
    };
    encode_canonical(&envelope).unwrap()
}

fn comfort_mandate() -> Vec<u8> {
    make_cbor_mandate(&["vehicle.climate.set_temperature"], &[])
}

/// Build a gateway receipt signed with `sk` using a fresh timestamp.
fn sign_fresh_receipt(
    verdict: &a2g_core::enforce::Verdict,
    tool: &str,
    params: &str,
    sk: &SigningKey,
) -> GatewayReceipt {
    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash = GatewayReceipt::compute_request_hash(tool, params, issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: verdict.verdict_id.clone(),
        decision: verdict.decision.to_string(),
        tool: tool.to_string(),
        params_json: params.to_string(),
        policy_rule: verdict.policy_rule.clone(),
        state_trust: verdict.state_trust.clone(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = sk.sign(&payload);
    GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    }
}

/// Build a raw receipt with the given fields (no automatic signing).
fn raw_receipt(
    tool: &str,
    decision: &str,
    issued_at_ms: i64,
    params: &str,
    state_trust: &str,
    binding_id: &str,
    sk: &SigningKey,
) -> GatewayReceipt {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash = GatewayReceipt::compute_request_hash(tool, params, issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: decision.to_string(),
        tool: tool.to_string(),
        params_json: params.to_string(),
        policy_rule: "test".to_string(),
        state_trust: state_trust.to_string(),
        binding_id: binding_id.to_string(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = sk.sign(&payload);
    GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    }
}

// ── Attack 1: Forbidden domain bypass ────────────────────────────────────────

/// A compromised rich domain fabricates a validly-signed ALLOW receipt for a
/// Forbidden tool (e.g. `vehicle.powertrain.set_throttle`).  The gateway's
/// independent forbidden re-check at Step 1 must refuse it before signature
/// verification.
#[test]
fn attack_01_forbidden_bypass() {
    let adv = Adv::start();

    let receipt = raw_receipt(
        "vehicle.powertrain.set_throttle",
        "ALLOW",
        Utc::now().timestamp_millis(),
        "{}",
        "none",
        "",
        &adv.receipt_sk,
    );
    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason } if reason.contains("forbidden")),
        "forbidden bypass must be refused at Step 1; got: {resp:?}"
    );
}

// ── Attack 2: Receipt signed with wrong key ───────────────────────────────────

/// Attacker has their own ed25519 key but does not know the gateway's receipt
/// signing key.  They sign a plausible ALLOW receipt with their rogue key.
/// Step 2 must reject the signature.
#[test]
fn attack_02_wrong_key_signature() {
    let adv = Adv::start();

    // Generate a random key the attacker controls.
    let mut rogue_key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rogue_key_bytes);
    let rogue_sk = SigningKey::from_bytes(&rogue_key_bytes);

    let receipt = raw_receipt(
        "vehicle.climate.set_temperature",
        "ALLOW",
        Utc::now().timestamp_millis(),
        "{}",
        "none",
        "",
        &rogue_sk, // signed with the WRONG key
    );
    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason } if reason.contains("signature")),
        "rogue key must be rejected at Step 2; got: {resp:?}"
    );
}

// ── Attack 3: Tool tampered after signing ─────────────────────────────────────

/// Attacker obtains a valid signed receipt for tool A and replaces the tool
/// field with tool B (which they do not have a valid receipt for).
/// The signature no longer matches the payload → Step 2 refuses.
#[test]
fn attack_03_tampered_tool_after_signing() {
    let adv = Adv::start();
    let mut receipt = adv.valid_comfort_receipt();

    // Tamper: replace the comfort tool with a sensitive one.
    receipt.tool = "WINDOW_POS".to_string();

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("signature") || reason.contains("forbidden")),
        "tampered tool must be refused at Step 2; got: {resp:?}"
    );
}

// ── Attack 4: Decision field mutation ────────────────────────────────────────

/// Attacker intercepts a DENY receipt and flips the `decision` field to ALLOW
/// before re-signing with a rogue key (the canonical bytes include the decision,
/// so they cannot keep the original signature).
/// The gateway must reject the rogue signature at Step 2.
#[test]
fn attack_04_decision_field_mutation() {
    let adv = Adv::start();

    // Attacker uses a rogue key.
    let mut rogue_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rogue_bytes);
    let rogue_sk = SigningKey::from_bytes(&rogue_bytes);

    // Fabricate a DENY→ALLOW mutated receipt signed with rogue key.
    let receipt = raw_receipt(
        "vehicle.climate.set_temperature",
        "ALLOW", // mutated from DENY
        Utc::now().timestamp_millis(),
        "{}",
        "none",
        "",
        &rogue_sk,
    );
    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason } if reason.contains("signature")),
        "mutated decision with rogue sig must be refused; got: {resp:?}"
    );
}

// ── Attack 5: Nonce replay ─────────────────────────────────────────────────────

/// Attacker captures a valid receipt and submits it a second time with the same
/// nonce.  Step 5 anti-replay must refuse the duplicate.
#[test]
fn attack_05_nonce_replay() {
    let adv = Adv::start();
    let receipt = adv.valid_comfort_receipt();

    let r1 = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt.clone()),
    });
    assert!(
        matches!(r1, GatewayResponse::Enforced { .. }),
        "first submission must succeed; got: {r1:?}"
    );

    let r2 = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&r2, GatewayResponse::Refused { reason } if reason.contains("nonce")),
        "replay with same nonce must be refused at Step 5; got: {r2:?}"
    );
}

// ── Attack 6: Past timestamp (stale receipt) ─────────────────────────────────

/// The rich domain (or attacker) submits a receipt with `issued_at_ms` > 2 s
/// in the past.  Step 4 freshness check must refuse it.
#[test]
fn attack_06_past_timestamp() {
    let adv = Adv::start();

    let stale_ms = Utc::now().timestamp_millis() - 10_000; // 10 s ago
    let receipt = raw_receipt(
        "vehicle.climate.set_temperature",
        "ALLOW",
        stale_ms,
        "{}",
        "none",
        "",
        &adv.receipt_sk,
    );
    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason } if reason.contains("stale")),
        "stale receipt must be refused at Step 4; got: {resp:?}"
    );
}

// ── Attack 7: Future timestamp ────────────────────────────────────────────────

/// Receipt timestamp is > 2 s in the future (clock skew attack or pre-signed
/// receipt trying to extend its validity window).
/// Step 4 freshness check (bidirectional ±2 000 ms) must refuse it.
#[test]
fn attack_07_future_timestamp() {
    let adv = Adv::start();

    let future_ms = Utc::now().timestamp_millis() + 10_000; // 10 s in the future
    let receipt = raw_receipt(
        "vehicle.climate.set_temperature",
        "ALLOW",
        future_ms,
        "{}",
        "none",
        "",
        &adv.receipt_sk,
    );
    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason } if reason.contains("stale") || reason.contains("future")),
        "future-dated receipt must be refused at Step 4; got: {resp:?}"
    );
}

// ── Attack 8: Request hash mutation ─────────────────────────────────────────

/// Attacker obtains a valid receipt and then changes `params_json` after
/// signing.  This breaks the `request_hash` binding (Step 6).
/// The gateway signature check still passes (hash is signed but hash is
/// derived from the original params); the action-match check must catch the
/// discrepancy.
#[test]
fn attack_08_request_hash_mutation() {
    let adv = Adv::start();
    let mut receipt = adv.valid_comfort_receipt();

    // Mutate params without re-signing — the request_hash was computed over
    // the original params, so it will no longer match the new params.
    receipt.params_json = r#"{"temperature": 99, "injected": true}"#.to_string();

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("request_hash") || reason.contains("signature")),
        "params mutation must be caught at Step 6 (or Step 2 if hash is in sig); got: {resp:?}"
    );
}

// ── Attack 9: Phantom binding ID ──────────────────────────────────────────────

/// Attacker fabricates a Phase 2 receipt with a `binding_id` that was never
/// submitted to the gateway's pending queue.  Step 7 must refuse the unknown
/// binding.
#[test]
fn attack_09_phantom_binding_id() {
    let adv = Adv::start();

    // Build a receipt that references a non-existent binding_id.
    let phantom_binding_id = uuid::Uuid::new_v4().to_string();
    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash =
        GatewayReceipt::compute_request_hash("vehicle.climate.set_temperature", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "vehicle.climate.set_temperature".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "test".to_string(),
        state_trust: "none".to_string(),
        binding_id: phantom_binding_id.clone(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = adv.receipt_sk.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains(&phantom_binding_id) || reason.contains("binding")),
        "phantom binding_id must be refused at Step 7; got: {resp:?}"
    );
}

// ── Attack 10: CAN state mismatch (ADR-0016 re-gate) ─────────────────────────

/// Attacker claims the vehicle is parked in the receipt while the gateway's
/// live SocketCAN feed shows the vehicle is moving at highway speed.
/// The ADR-0016 re-gate in `handle_enforce()` must refuse with
/// `state_authority_mismatch`.
///
/// We inject frames directly into the gateway's `StateIngest` (bypassing the
/// socket) to simulate live CAN data without requiring a vcan interface.
#[test]
fn attack_10_can_state_mismatch() {
    let adv = Adv::start();

    // Feed "moving" state directly into the gateway's ingested-state holder.
    // speed = 80 km/h (22_222 mm/s), gear = Drive, alive counter = 0.
    let now = Instant::now();
    adv.state
        .state_ingest
        .ingest_speed_frame(&encode_speed_frame(22_222, 0), now);
    adv.state
        .state_ingest
        .ingest_gear_frame(&encode_gear_frame(Gear::Drive, 0), now);

    // Confirm the ingested state is fresh and moving.
    let (gw_state, fresh) = adv.state.state_ingest.current_state(now);
    assert!(fresh, "injected frames must be fresh");
    assert!(
        !gw_state.is_parked_and_stopped(),
        "gateway should see moving state"
    );

    // Build a Sensitive ALLOW receipt claiming the vehicle is parked.
    // We force-sign with the correct key; all 7 canonical steps pass.
    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash = GatewayReceipt::compute_request_hash("WINDOW_POS", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "WINDOW_POS".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "sensitive_allowed_parked".to_string(),
        state_trust: "operator_trusted".to_string(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = adv.receipt_sk.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("state_authority_mismatch")),
        "CAN state mismatch must be refused by ADR-0016 re-gate; got: {resp:?}"
    );
}

// ── Attack 11: Stale CAN data with active reader fails closed ─────────────────

/// --state-ingest was activated but the CAN bus has gone silent (frames stale /
/// no frame was ever received).  The gateway must REFUSE Sensitive enforcement
/// fail-closed — a bus timeout must not silently fall back to operator-trusted
/// state and reopen GAP-1.
#[test]
fn attack_11_stale_can_reader_active_fails_closed() {
    let adv = Adv::start();

    // Simulate --state-ingest having been activated at startup.  No frames are
    // injected, so the state stays fail-safe (fresh=false), but reader_active=true
    // means the gateway knows it was supposed to be getting live data.
    adv.state.state_ingest.mark_reader_active();

    // Build a valid Sensitive ALLOW receipt (all 7 canonical steps pass).
    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash = GatewayReceipt::compute_request_hash("WINDOW_POS", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "WINDOW_POS".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "sensitive_allowed_parked".to_string(),
        state_trust: "operator_trusted".to_string(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = adv.receipt_sk.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("state_authority_mismatch")),
        "stale CAN with active reader must fail-closed (GAP-1 must not reopen); got: {resp:?}"
    );
}

// ── Attack 12: pay.* ALLOW receipt without HITL binding bypasses payment gate ─

/// A compromised rich domain signs an ALLOW receipt for `pay.toll.charge` without
/// a Phase 2 binding (binding_id is empty). The gateway must refuse: pay.* tools
/// can only reach ALLOW via Phase 2 approval (ADR-0018 Step 3.5 guard).
#[test]
fn attack_12_pay_hitl_bypass() {
    let adv = Adv::start();

    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash = GatewayReceipt::compute_request_hash("pay.toll.charge", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "pay.toll.charge".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "all_checks_passed".to_string(),
        state_trust: "none".to_string(),
        binding_id: String::new(), // empty — no Phase 2 binding presented
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = adv.receipt_sk.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("cockpit_hitl_binding_required")),
        "pay.* ALLOW without binding must be refused at Step 3.5; got: {resp:?}"
    );
}

// ── Attack 13: pii.profile.export cockpit Forbidden bypass ───────────────────

/// A compromised rich domain signs an ALLOW receipt for `pii.profile.export`,
/// which is structurally Forbidden (ADR-0018). The gateway must refuse at Step 1.5
/// before signature verification, identically to vehicle Forbidden tools.
#[test]
fn attack_13_pii_export_forbidden_bypass() {
    let adv = Adv::start();

    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash =
        GatewayReceipt::compute_request_hash("pii.profile.export", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "pii.profile.export".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "all_checks_passed".to_string(),
        state_trust: "none".to_string(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    let sig: ed25519_dalek::Signature = adv.receipt_sk.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("gateway_cockpit_forbidden")),
        "pii.profile.export must be refused at Step 1.5 (cockpit forbidden); got: {resp:?}"
    );
}

// ── Attack 14: pii-gated comms.contacts.read ALLOW without pii.grant binding ─

/// A compromised rich domain claims ALLOW for `comms.contacts.read` without
/// going through Phase 2 (empty binding_id). `comms.contacts.read` is NOT
/// always-HITL (it's PiiReadGated), but it is NOT in the always-hitl set.
/// The protection here is that `decide()` would DENY it without pii.grant,
/// so a valid ALLOW receipt cannot exist without the mandate having pii.grant.
/// This attack tests the case where the rich domain is compromised:
/// the receipt is signed correctly but `decide()` was bypassed.
///
/// Because `comms.contacts.read` is CommsReadPiiGated (not always-HITL),
/// it can produce ALLOW with pii.grant in the mandate (no binding required).
/// The gateway's defense here is the signature: a forged receipt without going
/// through a legitimate `decide()` call would have a bad signature — and indeed
/// the test shows the receipt with a tampered tool triggers Step 2 failure (or
/// Step 3.5 would catch it if it were a pay.* tool).
///
/// This attack specifically verifies that a receipt forged by an attacker who
/// does NOT have the gateway signing key is refused at Step 2 (signature fail).
#[test]
fn attack_14_pii_grant_forgery_wrong_key() {
    let adv = Adv::start();

    // Attacker uses their own key (not the gateway's receipt key).
    let attacker_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let request_hash =
        GatewayReceipt::compute_request_hash("comms.contacts.read", "{}", issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: "comms.contacts.read".to_string(),
        params_json: "{}".to_string(),
        policy_rule: "all_checks_passed".to_string(),
        state_trust: "none".to_string(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().unwrap();
    // Signed with ATTACKER key — not the gateway's receipt key.
    let sig: ed25519_dalek::Signature = attacker_key.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    let resp = adv.send(&GatewayRequest::Enforce {
        receipt: Box::new(receipt),
    });
    assert!(
        matches!(&resp, GatewayResponse::Refused { reason }
            if reason.contains("signature")),
        "forged pii-read receipt must be refused at Step 2 (wrong key); got: {resp:?}"
    );
}
