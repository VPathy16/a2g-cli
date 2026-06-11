//! Four-beat governance showcase.
//!
//! Each beat runs a scripted scenario through the real pipeline:
//!   core decide() → signed GatewayReceipt → gateway socket → bus write / refuse
//!
//! Beat 1 — Comfort ALLOW:        temperature set → ALLOW → frame on bus
//! Beat 2 — State-gated DENY:     window open at 120 kph → DENY from core → bus silent
//! Beat 3 — Forbidden HARD-DENY:  throttle command, valid sig → gateway step-1 refuse → bus silent
//! Beat 4 — Sensitive HITL:       door unlock in park → PendingApproval → grant → ALLOW → frame

use std::io::{self, Write};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use a2g_core::enforce::{decide, decide_with_approval, TrustAnchor};
use a2g_core::hitl::ApprovalGrant;
use a2g_core::ledger::NoopLedger;
use a2g_core::vehicle::{Actor, Gear, VehicleState, VerifiedVehicleState};
use a2g_gateway::client::{send_request, sign_receipt_with_params};
use a2g_gateway::keys::{generate, DemoKeys};
use a2g_gateway::protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};
use a2g_gateway::server::{serve, GatewayState};
use chrono::Utc;
use ed25519_dalek::Signer;
use rand::RngCore;

// ── ANSI colour helpers ───────────────────────────────────────────────────────

const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const CYAN: &str = "\x1b[96m";
const RED: &str = "\x1b[91m";
const MAGENTA: &str = "\x1b[95m";
const BLUE: &str = "\x1b[94m";

// ── Public result type (used by CI tests) ────────────────────────────────────

/// Outcome of each beat, returned for programmatic verification.
pub struct ShowcaseResults {
    /// Beat 1: gateway response for the comfort ALLOW.
    pub beat1: GatewayResponse,
    /// Beat 2: core verdict decision string ("DENY").
    pub beat2_core_decision: String,
    /// Beat 3: gateway response for the fabricated forbidden receipt.
    pub beat3: GatewayResponse,
    /// Beat 4: gateway response for the Phase-2 ALLOW.
    pub beat4: GatewayResponse,
}

// ── Top-level entry points ────────────────────────────────────────────────────

/// Start an embedded gateway, run all four beats, then shut down.
/// This is what `a2g-demo run` calls.
pub fn run(vcan_iface: &str, pause: bool) {
    let socket_path = std::env::temp_dir().join(format!("a2g-demo-{}.sock", uuid::Uuid::new_v4()));
    let key_path =
        std::env::temp_dir().join(format!("a2g-demo-keys-{}.json", uuid::Uuid::new_v4()));

    let (gw_keys, demo_keys) = generate(&key_path);
    let state = Arc::new(GatewayState::new(gw_keys, demo_keys.clone(), vcan_iface));
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let state_c = Arc::clone(&state);
    let sock_c = socket_path.clone();
    thread::spawn(move || serve(state_c, &sock_c, ready_tx, shutdown_rx));
    ready_rx.recv().expect("embedded gateway ready");

    print_intro(vcan_iface);
    run_with_gateway(&socket_path, &demo_keys, pause);

    let _ = shutdown_tx.send(());
    thread::sleep(Duration::from_millis(50));
}

/// Run beats against an already-running gateway.  Used by both `run()` and CI tests.
pub fn run_with_gateway(socket_path: &Path, demo_keys: &DemoKeys, pause: bool) -> ShowcaseResults {
    let b1 = beat1_comfort_allow(socket_path, demo_keys);
    maybe_pause(pause);

    let b2_decision = beat2_state_gated_deny(socket_path, demo_keys);
    maybe_pause(pause);

    let b3 = beat3_forbidden_hard_deny(socket_path, demo_keys);
    maybe_pause(pause);

    let b4 = beat4_hitl_door_unlock(socket_path, demo_keys);

    print_finale();

    ShowcaseResults {
        beat1: b1,
        beat2_core_decision: b2_decision,
        beat3: b3,
        beat4: b4,
    }
}

// ── Beat implementations ──────────────────────────────────────────────────────

fn beat1_comfort_allow(socket_path: &Path, demo_keys: &DemoKeys) -> GatewayResponse {
    print_beat_header(
        1,
        "COMFORT ACTION",
        "Expected: ALLOW → CAN frame on bus",
        "Routine cabin control. No vehicle-state constraints. Always permitted.",
    );

    let tool = "vehicle.climate.set_temperature";
    let params_json = r#"{"target_celsius": 22}"#;
    let mandate = make_mandate(&[tool], &[]);

    println!("  {GREEN}[AGENT]{RESET} tool:   {BOLD}{tool}{RESET}");
    println!("  {GREEN}[AGENT]{RESET} params: {params_json}");
    println!("  {GREEN}[AGENT]{RESET} intent: \"Set cabin temperature to 22 °C\"");
    println!();

    let params: serde_json::Value = serde_json::from_str(params_json).unwrap();
    let verdict = decide(
        &mandate,
        tool,
        &params,
        &NoopLedger,
        Utc::now(),
        None,
        &TrustAnchor::SelfSovereign,
    )
    .unwrap();

    println!(
        "  {YELLOW}[CORE]{RESET}  decision:    {BOLD}{}{RESET}",
        verdict.decision
    );
    println!(
        "  {YELLOW}[CORE]{RESET}  rule:        {}",
        verdict.policy_rule
    );
    println!(
        "  {YELLOW}[CORE]{RESET}  state_trust: {}",
        verdict.state_trust
    );
    println!();

    let key = demo_keys.receipt_signing_key();
    let receipt = sign_receipt_with_params(&verdict, params_json, "", &key, None);
    println!(
        "  {GREEN}[AGENT]{RESET} signed receipt  verdict_id={}{RESET}",
        &verdict.verdict_id[..8]
    );

    println!("  {CYAN}[GW]{RESET}    submitting to gateway ...");
    let resp = send_request(
        socket_path,
        &GatewayRequest::Enforce {
            receipt: Box::new(receipt),
        },
    );

    match &resp {
        GatewayResponse::Enforced {
            frame_hex,
            real_write,
            ..
        } => {
            println!("  {CYAN}[GW]{RESET}    {BOLD}{MAGENTA}✓ ENFORCED{RESET}");
            println!("  {CYAN}[GW]{RESET}    frame_hex:  {MAGENTA}{BOLD}{frame_hex}{RESET}");
            if *real_write {
                println!("  {CYAN}[GW]{RESET}    {MAGENTA}real_write: true  ← real CAN frame written to vcan0{RESET}");
                println!();
                println!("  {MAGENTA}{BOLD}[BUS]   ← Frame should now appear in the listener pane.{RESET}");
            } else {
                println!(
                    "  {CYAN}[GW]{RESET}    {DIM}real_write: false  (vcan0 not available — simulated bus){RESET}"
                );
                println!();
                println!("  {DIM}[BUS]   Simulated frame logged to gateway stdout.{RESET}");
                println!("  {DIM}        Run on a host with vcan0 to see a real frame in the listener pane.{RESET}");
            }
        }
        other => {
            println!("  {RED}[GW]    UNEXPECTED response: {other:?}{RESET}");
        }
    }

    println!();
    resp
}

fn beat2_state_gated_deny(socket_path: &Path, demo_keys: &DemoKeys) -> String {
    let _ = (socket_path, demo_keys); // beat 2 stops at core; no gateway call needed

    print_beat_header(
        2,
        "STATE-GATED DENY",
        "Expected: DENY from core → bus silent",
        "Vehicle is moving at 120 kph. Sensitive actions (window, door) require park+stopped.",
    );

    let tool = "vehicle.window.set_position";
    let params_json = r#"{"position_pct": 100}"#;
    let mandate = make_mandate(&[tool], &[]);
    let moving = VerifiedVehicleState::from_operator_trusted(VehicleState {
        speed_mmps: 33_333, // 120.0 km/h
        gear: Gear::Drive,
        actor: Actor::Driver,
    });

    println!("  {GREEN}[AGENT]{RESET} tool:   {BOLD}{tool}{RESET}");
    println!("  {GREEN}[AGENT]{RESET} params: {params_json}");
    println!("  {GREEN}[AGENT]{RESET} intent: \"Open windows fully\"");
    println!("  {GREEN}[AGENT]{RESET} state:  speed=120 kph, gear=Drive");
    println!();

    let params: serde_json::Value = serde_json::from_str(params_json).unwrap();
    let verdict = decide(
        &mandate,
        tool,
        &params,
        &NoopLedger,
        Utc::now(),
        Some(&moving),
        &TrustAnchor::SelfSovereign,
    )
    .unwrap();

    println!(
        "  {YELLOW}[CORE]{RESET}  decision:    {BOLD}{RED}{}  ← vehicle state violation{RESET}",
        verdict.decision
    );
    println!(
        "  {YELLOW}[CORE]{RESET}  rule:        {}",
        verdict.policy_rule
    );
    println!();
    println!("  {GREEN}[AGENT]{RESET} Core returned DENY. Honest agent stops here.");
    println!("  {GREEN}[AGENT]{RESET} No receipt is submitted to the gateway.");
    println!();
    println!("  {DIM}[BUS]   ← Silent. No frame. The decision never reached the gateway.{RESET}");
    println!("  {DIM}        The bus listener pane shows nothing.{RESET}");
    println!();

    verdict.decision.to_string()
}

fn beat3_forbidden_hard_deny(socket_path: &Path, demo_keys: &DemoKeys) -> GatewayResponse {
    print_beat_header(
        3,
        "FORBIDDEN — GATEWAY INDEPENDENT HARD-DENY",
        "Expected: REFUSE at gateway step 1 → bus silent",
        "The headline beat. Read the narration.",
    );

    let tool = "vehicle.powertrain.set_throttle";
    let params_json = r#"{"throttle_pct": 80}"#;

    println!("  {GREEN}[AGENT]{RESET} tool:   {BOLD}{tool}{RESET}");
    println!("  {GREEN}[AGENT]{RESET} params: {params_json}");
    println!("  {GREEN}[AGENT]{RESET} intent: \"Increase engine throttle to 80%\"");
    println!();
    println!(
        "  {YELLOW}[NOTE]{RESET}  {BOLD}This tool is in the FORBIDDEN domain (propulsion).{RESET}"
    );
    println!(
        "  {YELLOW}[NOTE]{RESET}  Normally a2g-core would deny it before the agent even signs."
    );
    println!("  {YELLOW}[NOTE]{RESET}  We are now simulating a compromised or buggy rich domain");
    println!(
        "  {YELLOW}[NOTE]{RESET}  that bypasses core's check and fabricates a valid ALLOW receipt."
    );
    println!();
    println!("  {GREEN}[AGENT]{RESET} Fabricating receipt with decision=ALLOW ...");

    let key = demo_keys.receipt_signing_key();
    let issued_at_ms = Utc::now().timestamp_millis();
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);
    let request_hash = GatewayReceipt::compute_request_hash(tool, params_json, issued_at_ms);
    let partial = GatewayReceipt {
        verdict_id: uuid::Uuid::new_v4().to_string(),
        decision: "ALLOW".to_string(),
        tool: tool.to_string(),
        params_json: params_json.to_string(),
        policy_rule: "bypassed_by_demo_agent".to_string(),
        state_trust: "none".to_string(),
        binding_id: String::new(),
        request_hash,
        issued_at_ms,
        nonce_hex,
        signature_hex: String::new(),
        attested_state_json: None,
    };
    let payload = partial.canonical_bytes().expect("canonical_bytes");
    let sig: ed25519_dalek::Signature = key.sign(&payload);
    let receipt = GatewayReceipt {
        signature_hex: hex::encode(sig.to_bytes()),
        ..partial
    };

    println!("  {GREEN}[AGENT]{RESET} {BOLD}Receipt signed with the real gateway key.{RESET}");
    println!("  {GREEN}[AGENT]{RESET} This signature is genuine — it will pass step 2.");
    println!("  {GREEN}[AGENT]{RESET} Submitting to gateway ...");
    println!();

    let resp = send_request(
        socket_path,
        &GatewayRequest::Enforce {
            receipt: Box::new(receipt),
        },
    );

    match &resp {
        GatewayResponse::Refused { reason } => {
            println!("  {CYAN}[GW]{RESET}    {BOLD}{RED}✗ REFUSED — step 1: independent forbidden re-check{RESET}");
            println!("  {CYAN}[GW]{RESET}    reason: \"{reason}\"");
            println!();
            println!("  {YELLOW}[NOTE]{RESET}  The gateway checked forbidden status {BOLD}BEFORE{RESET} verifying the");
            println!("  {YELLOW}[NOTE]{RESET}  signature. Even a receipt with a genuine, valid signature");
            println!("  {YELLOW}[NOTE]{RESET}  for a forbidden action is refused unconditionally.");
            println!();
            println!("  {RED}{BOLD}[BUS]   ← SILENT.  No frame.  Not now.  Not ever for this action.{RESET}");
            println!("  {RED}        The bus listener pane shows nothing.{RESET}");
            println!("  {RED}        This action is structurally forbidden regardless of what");
            println!("  {RED}        the agent presents.  The bus never sees it.{RESET}");
        }
        other => {
            println!("  {RED}[GW]    UNEXPECTED response (should be Refused): {other:?}{RESET}");
        }
    }

    println!();
    resp
}

fn beat4_hitl_door_unlock(socket_path: &Path, demo_keys: &DemoKeys) -> GatewayResponse {
    print_beat_header(
        4,
        "SENSITIVE ACTION — HUMAN-IN-THE-LOOP",
        "Expected: PendingApproval → grant → ALLOW → CAN frame",
        "Door unlock requires human approval. Vehicle is parked.",
    );

    let tool = "vehicle.door.unlock";
    let params_json = r#"{"door": "all"}"#;
    let mandate = make_mandate(&[tool], &[tool]);
    let parked = VerifiedVehicleState::from_operator_trusted(VehicleState {
        speed_mmps: 0,
        gear: Gear::Park,
        actor: Actor::Driver,
    });

    println!("  {GREEN}[AGENT]{RESET} tool:   {BOLD}{tool}{RESET}");
    println!("  {GREEN}[AGENT]{RESET} params: {params_json}");
    println!("  {GREEN}[AGENT]{RESET} intent: \"Unlock all doors\"");
    println!("  {GREEN}[AGENT]{RESET} state:  speed=0 kph, gear=Park");
    println!();

    // Phase 1: decide → PendingApproval
    let params: serde_json::Value = serde_json::from_str(params_json).unwrap();
    let v1 = decide(
        &mandate,
        tool,
        &params,
        &NoopLedger,
        Utc::now(),
        Some(&parked),
        &TrustAnchor::SelfSovereign,
    )
    .unwrap();

    println!(
        "  {YELLOW}[CORE]{RESET}  decision:    {BOLD}{YELLOW}{}  ← waiting for human{RESET}",
        v1.decision
    );
    let binding = v1
        .pending_approval
        .as_ref()
        .expect("PendingApproval must carry a binding");
    println!(
        "  {YELLOW}[CORE]{RESET}  binding_id:  {}",
        &binding.binding_id[..8]
    );
    println!();

    // Present binding to gateway for signing and queuing
    println!("  {GREEN}[AGENT]{RESET} → gateway: SignBinding request ...");
    let binding_json = serde_json::to_string(binding).unwrap();
    let sign_resp = send_request(socket_path, &GatewayRequest::SignBinding { binding_json });
    let _signed_json = match &sign_resp {
        GatewayResponse::SignedBinding { signed_json } => {
            println!("  {CYAN}[GW]{RESET}    binding signed and queued ✓");
            signed_json.clone()
        }
        other => {
            println!("  {RED}[GW]    unexpected: {other:?}{RESET}");
            return GatewayResponse::Error {
                message: format!("{other:?}"),
            };
        }
    };
    println!();

    // Operator constructs and signs the approval grant
    println!("  {BLUE}[HUMAN]{RESET} {BOLD}Reviewing approval request:{RESET}");
    println!("  {BLUE}[HUMAN]{RESET}   action:    {tool}");
    println!("  {BLUE}[HUMAN]{RESET}   params:    {params_json}");
    println!("  {BLUE}[HUMAN]{RESET}   vehicle:   parked, stopped");
    println!("  {BLUE}[HUMAN]{RESET}   ttl:       5 minutes");
    println!("  {BLUE}[HUMAN]{RESET} Signing ApprovalGrant with operator key ...");

    let op_key = demo_keys.operator_signing_key();
    let operator_did = format!(
        "did:a2g:{}",
        bs58::encode(op_key.verifying_key().to_bytes()).into_string()
    );
    let grant = ApprovalGrant::new_signed(
        &binding.binding_id,
        &binding.request_hash,
        &operator_did,
        &op_key,
        300,
        Utc::now(),
        &v1.verdict_id,
    )
    .expect("demo grant must sign");
    println!("  {BLUE}[HUMAN]{RESET} {BOLD}Grant signed.  Submitting to gateway ...{RESET}");
    println!();

    let grant_json = serde_json::to_string(&grant).unwrap();
    let grant_resp = send_request(socket_path, &GatewayRequest::SubmitGrant { grant_json });
    match &grant_resp {
        GatewayResponse::GrantAccepted { binding_id } => {
            println!(
                "  {CYAN}[GW]{RESET}    grant accepted, binding {} approved ✓",
                &binding_id[..8]
            );
        }
        other => {
            println!("  {RED}[GW]    unexpected: {other:?}{RESET}");
            return GatewayResponse::Error {
                message: format!("{other:?}"),
            };
        }
    }
    println!();

    // Phase 2: decide_with_approval → ALLOW
    let v2 = decide_with_approval(
        &mandate,
        tool,
        &params,
        &NoopLedger,
        Utc::now(),
        Some(&parked),
        binding,
        &grant,
        &TrustAnchor::SelfSovereign,
    )
    .unwrap();

    println!(
        "  {YELLOW}[CORE]{RESET}  Phase-2 decision: {BOLD}{GREEN}{}  ← approved{RESET}",
        v2.decision
    );
    println!();

    // Sign and submit Phase 2 receipt
    let key = demo_keys.receipt_signing_key();
    let receipt = sign_receipt_with_params(&v2, params_json, &binding.binding_id, &key, None);
    println!(
        "  {GREEN}[AGENT]{RESET} Phase-2 receipt signed (binding_id={})",
        &binding.binding_id[..8]
    );
    println!("  {CYAN}[GW]{RESET}    submitting Phase-2 enforcement ...");

    let resp = send_request(
        socket_path,
        &GatewayRequest::Enforce {
            receipt: Box::new(receipt),
        },
    );

    match &resp {
        GatewayResponse::Enforced {
            frame_hex,
            real_write,
            ..
        } => {
            println!("  {CYAN}[GW]{RESET}    {BOLD}{MAGENTA}✓ ENFORCED — Phase-2 ALLOW{RESET}");
            println!("  {CYAN}[GW]{RESET}    frame_hex:  {MAGENTA}{BOLD}{frame_hex}{RESET}");
            if *real_write {
                println!("  {CYAN}[GW]{RESET}    {MAGENTA}real_write: true  ← real CAN frame written to vcan0{RESET}");
                println!();
                println!("  {MAGENTA}{BOLD}[BUS]   ← Frame should now appear in the listener pane.{RESET}");
            } else {
                println!(
                    "  {CYAN}[GW]{RESET}    {DIM}real_write: false  (vcan0 not available — simulated bus){RESET}"
                );
                println!();
                println!("  {DIM}[BUS]   Simulated frame logged to gateway stdout.{RESET}");
            }
        }
        other => {
            println!("  {RED}[GW]    UNEXPECTED: {other:?}{RESET}");
        }
    }

    println!();
    resp
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_mandate(tools: &[&str], escalate_tools: &[&str]) -> Vec<u8> {
    use a2g_core::cbor::{encode_canonical, CborMandate, MandateTbs};
    use a2g_core::mandate::capabilities_hash;
    use ed25519_dalek::{Signer, SigningKey};
    use minicbor::bytes::ByteVec;

    let (did, _, _) = a2g_core::identity::generate_agent_keypair();
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let issuer_did = format!("did:a2g:{}", bs58::encode(&pubkey_bytes).into_string());

    let tools_owned: Vec<String> = tools.iter().map(|t| t.to_string()).collect();
    let escalate_owned: Vec<String> = escalate_tools.iter().map(|t| t.to_string()).collect();

    let now = chrono::Utc::now();
    let expires_at = now
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap_or(now);

    let cap_hash_hex = capabilities_hash(&tools_owned);
    let cap_hash_bytes = hex::decode(&cap_hash_hex).unwrap();

    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did: did.clone(),
        issuer_did: issuer_did.clone(),
        agent_name: "demo-agent".to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        proposal_hash: String::new(),
        workspace_root: String::new(),
        capabilities_hash: ByteVec::from(cap_hash_bytes),
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
        escalate_tools: escalate_owned,
        escalate_paths: vec![],
        escalate_hosts: vec![],
        escalate_to: String::new(),
    };

    let tbs_bytes = encode_canonical(&tbs).unwrap();
    let signature = signing_key.sign(&tbs_bytes);
    let sig_bytes = signature.to_bytes().to_vec();

    let envelope = CborMandate {
        tag: "MANDATE-V1".to_string(),
        tbs: ByteVec::from(tbs_bytes),
        signature: ByteVec::from(sig_bytes),
        issuer_pubkey: ByteVec::from(pubkey_bytes.to_vec()),
    };

    encode_canonical(&envelope).unwrap()
}

fn print_beat_header(num: u8, title: &str, expected: &str, description: &str) {
    let line = "─".repeat(62);
    println!("{BOLD}{line}{RESET}");
    println!("{BOLD} BEAT {num} of 4  ·  {title}{RESET}");
    println!(" {DIM}{expected}{RESET}");
    println!("{BOLD}{line}{RESET}");
    println!();
    println!("  {description}");
    println!();
}

fn print_intro(vcan_iface: &str) {
    let line = "━".repeat(62);
    println!();
    println!("{BOLD}{BLUE}{line}{RESET}");
    println!("{BOLD}{BLUE}  A2G GOVERNANCE DEMO — Agent-to-Gateway Enforcement Pipeline{RESET}");
    println!("{BOLD}{BLUE}{line}{RESET}");
    println!();
    println!("  You are watching a live governance pipeline.");
    println!();
    println!("  An AI agent requests vehicle capabilities. A cryptographic");
    println!("  policy engine (a2g-core) decides whether each request is");
    println!("  permitted. A separate enforcement gateway independently");
    println!("  verifies the decision before anything touches the CAN bus.");
    println!();
    println!("  Enforced ALLOWs produce CAN frames on {vcan_iface}.");
    println!("  Denied and forbidden actions leave the bus completely silent.");
    println!("  The silence is the guarantee.");
    println!();
    println!("  {DIM}(embedded gateway started; vcan={vcan_iface}){RESET}");
    println!();
}

fn print_finale() {
    let line = "━".repeat(62);
    println!("{BOLD}{BLUE}{line}{RESET}");
    println!("{BOLD}{BLUE}  SHOWCASE COMPLETE{RESET}");
    println!("{BOLD}{BLUE}{line}{RESET}");
    println!();
    println!("  Beat 1  Comfort ALLOW     → {MAGENTA}{BOLD}frame on bus{RESET}");
    println!("  Beat 2  State-gated DENY  → {DIM}bus silent (core denied){RESET}");
    println!(
        "  Beat 3  Forbidden DENY    → {RED}{BOLD}bus silent (gateway independent re-check){RESET}"
    );
    println!(
        "  Beat 4  HITL ALLOW        → {MAGENTA}{BOLD}frame on bus (after human approval){RESET}"
    );
    println!();
    println!("  Two beats enforced. Two beats silent. The bus is the record.");
    println!();
}

fn maybe_pause(pause: bool) {
    if pause {
        print!("  {DIM}Press Enter for next beat ...{RESET}  ");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut String::new());
    } else {
        thread::sleep(Duration::from_millis(300));
    }
}
