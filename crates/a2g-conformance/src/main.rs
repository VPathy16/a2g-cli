//! A2G Protocol Conformance Runner (SPEC.md §10)
//!
//! Feeds each JSON test vector in conformance/vectors/ through the reference
//! implementation and reports PASS / FAIL / KNOWN_FAIL per vector.
//!
//! Exit code 0 when all non-known-failing vectors pass; exit code 1 when any
//! unexpected failure is detected so CI gates on it.

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};

use a2g_core::enforce::{decide, decide_with_approval, Decision};
use a2g_core::hitl::ApprovalGrant;
use a2g_core::identity::generate_agent_keypair;
use a2g_core::ledger::NoopLedger;
use a2g_core::mandate;
use a2g_core::vehicle::{Actor, Gear, VehicleState, VerifiedVehicleState};
use a2g_gateway::client::{send_request, sign_receipt_with_params};
use a2g_gateway::keys::generate;
use a2g_gateway::protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};
use a2g_gateway::server::{serve, GatewayState};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// ── Test vector schema ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TestVector {
    id: String,
    spec_ref: String,
    #[allow(dead_code)]
    category: String,
    description: String,
    #[serde(default)]
    known_failing: bool,
    #[allow(dead_code)]
    #[serde(default)]
    known_failing_reason: Option<String>,
    input: VectorInput,
    expected: VectorExpected,
}

#[derive(Debug, Deserialize)]
struct VectorInput {
    mandate_capabilities: Vec<String>,
    #[serde(default)]
    mandate_escalate_tools: Vec<String>,
    mandate_expires_in_hours: i64,
    #[serde(default)]
    mandate_bad_signature: bool,
    #[serde(default)]
    mandate_use_spec_signing: bool,
    mandate_workspace_root: Option<String>,
    mandate_operating_hours: Option<String>,
    mandate_rate_limit: u64,
    #[serde(default)]
    mandate_fs_deny: Vec<String>,
    #[serde(default)]
    mandate_fs_read: Vec<String>,
    #[serde(default)]
    mandate_fs_write: Vec<String>,
    capability: String,
    params: serde_json::Value,
    state_speed_kph: Option<f64>,
    state_gear: Option<String>,
    state_actor: Option<String>,
    #[allow(dead_code)]
    state_trust: Option<String>,
    #[serde(default)]
    clock_offset_seconds: i64,
    phase2_grant_type: Option<String>,
    gateway_test_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VectorExpected {
    verdict: String,
    policy_rule_contains: Option<String>,
    gateway_enforced: Option<bool>,
    gateway_refused_reason_contains: Option<String>,
}

// ── Test outcomes ─────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Outcome {
    Pass,
    Fail(String),
    KnownFail(String),
}

// ── Mandate construction ──────────────────────────────────────────────────────

/// Build and sign a mandate from vector input fields.
///
/// Returns `(signed_mandate_toml, sovereign_secret_hex)` so callers can tamper
/// the signature for bad-sig vectors.
fn build_mandate(input: &VectorInput) -> (String, String) {
    let (agent_did, _, _) = generate_agent_keypair();
    let (_, sovereign_secret, _) = generate_agent_keypair();

    let tools_toml: String = input
        .mandate_capabilities
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let escalate_tools_toml: String = input
        .mandate_escalate_tools
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let workspace_root = input
        .mandate_workspace_root
        .as_deref()
        .unwrap_or("")
        .to_string();

    let operating_hours = input
        .mandate_operating_hours
        .as_deref()
        .unwrap_or("")
        .to_string();

    let escalate_to = if input.mandate_escalate_tools.is_empty() {
        String::new()
    } else {
        "did:a2g:conformance-approver".to_string()
    };

    let fs_deny_toml: String = input
        .mandate_fs_deny
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let fs_read_toml: String = input
        .mandate_fs_read
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let fs_write_toml: String = input
        .mandate_fs_write
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let template = format!(
        r#"[mandate]
version = "0.1.0"
agent_did = "{agent_did}"
agent_name = "conformance-test"
workspace_root = "{workspace_root}"

[capabilities]
tools = [{tools_toml}]

[boundaries]
fs_deny = [{fs_deny_toml}]
fs_read = [{fs_read_toml}]
fs_write = [{fs_write_toml}]

[limits]
max_calls_per_minute = {rate_limit}

[jurisdiction]
operating_hours = "{operating_hours}"

[escalation]
escalate_tools = [{escalate_tools_toml}]
escalate_to = "{escalate_to}"
"#,
        agent_did = agent_did,
        tools_toml = tools_toml,
        workspace_root = workspace_root,
        fs_deny_toml = fs_deny_toml,
        fs_read_toml = fs_read_toml,
        fs_write_toml = fs_write_toml,
        rate_limit = input.mandate_rate_limit,
        operating_hours = operating_hours,
        escalate_tools_toml = escalate_tools_toml,
        escalate_to = escalate_to,
    );

    let ttl = input.mandate_expires_in_hours.max(0) as u64;
    let signed = mandate::sign_mandate(&template, &sovereign_secret, ttl).expect("sign_mandate");

    (signed, sovereign_secret)
}

/// Tamper with a signed mandate's signature bytes so it fails verification.
fn tamper_signature(signed_toml: &str) -> String {
    // Find the signature = "..." line and flip the first two hex chars
    signed_toml
        .lines()
        .map(|line| {
            if line.starts_with("signature = \"") {
                // Flip the first hex byte: 00→ff, ff→00, else swap nibbles
                let inner = line
                    .trim_start_matches("signature = \"")
                    .trim_end_matches('"');
                let tampered: String = if inner.len() >= 2 {
                    let first_byte = &inner[..2];
                    let tampered_byte = if first_byte == "00" {
                        "ff".to_string()
                    } else {
                        "00".to_string()
                    };
                    format!("{}{}", tampered_byte, &inner[2..])
                } else {
                    inner.to_string()
                };
                format!("signature = \"{tampered}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build a mandate signed with the SPEC §4.5 canonical payload.
///
/// After the fix/mandate-signing-payload change, the implementation now uses this
/// same canonical format, so this function and `build_mandate` produce compatible
/// mandates. The function is kept separate so mv-004 explicitly exercises the
/// spec-canonical path end-to-end.
fn build_spec_signed_mandate(input: &VectorInput) -> String {
    use chrono::Duration;
    use ed25519_dalek::Signer;

    let (agent_did, _, _) = generate_agent_keypair();
    let (_, sovereign_secret_hex, sovereign_pubkey_hex) = generate_agent_keypair();
    let secret_bytes = hex::decode(&sovereign_secret_hex).unwrap();
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&secret_arr);

    let now = Utc::now();
    let expires_at = (now + Duration::hours(input.mandate_expires_in_hours)).to_rfc3339();

    let issuer_pubkey_bytes = hex::decode(&sovereign_pubkey_hex).unwrap();
    let issuer_did = format!(
        "did:a2g:{}",
        bs58::encode(&issuer_pubkey_bytes).into_string()
    );

    // capabilities_hash: sort lexicographically, join with \n, SHA-256 (SPEC §4.5)
    let cap_hash = a2g_core::mandate::capabilities_hash(&input.mandate_capabilities);

    // Spec-canonical signing payload (§4.5)
    let canonical = format!("MANDATE:{agent_did}:{issuer_did}:{expires_at}:{cap_hash}");
    let payload_hash = Sha256::digest(canonical.as_bytes());
    let sig: ed25519_dalek::Signature = signing_key.sign(&payload_hash);
    let sig_hex = hex::encode(sig.to_bytes());

    let tools_toml: String = input
        .mandate_capabilities
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"[mandate]
version = "0.1.0"
agent_did = "{agent_did}"
agent_name = "conformance-spec-sign-test"
issued_at = "{issued_at}"
expires_at = "{expires_at}"
issuer = "{issuer_did}"

[capabilities]
tools = [{tools_toml}]

[boundaries]

[limits]
max_calls_per_minute = {rate_limit}

[jurisdiction]
operating_hours = ""

[escalation]
escalate_tools = []
escalate_to = ""

[signature]
algorithm = "ed25519"
issuer_pubkey = "{sovereign_pubkey_hex}"
signature = "{sig_hex}"
signed_at = "{issued_at}"
"#,
        agent_did = agent_did,
        issued_at = now.to_rfc3339(),
        expires_at = expires_at,
        issuer_did = issuer_did,
        tools_toml = tools_toml,
        rate_limit = input.mandate_rate_limit,
        sovereign_pubkey_hex = sovereign_pubkey_hex,
        sig_hex = sig_hex,
    )
}

// ── Vehicle state ─────────────────────────────────────────────────────────────

fn build_vehicle_state(input: &VectorInput) -> Option<VerifiedVehicleState> {
    let speed_kph = input.state_speed_kph?;
    let gear = match input.state_gear.as_deref().unwrap_or("Park") {
        "Park" => Gear::Park,
        "Drive" => Gear::Drive,
        "Reverse" => Gear::Reverse,
        "Neutral" => Gear::Neutral,
        _ => Gear::Park,
    };
    let actor = match input.state_actor.as_deref().unwrap_or("Driver") {
        "Driver" => Actor::Driver,
        "Passenger" => Actor::Passenger,
        _ => Actor::Driver,
    };
    let state = VehicleState {
        speed_kph,
        gear,
        actor,
    };
    Some(VerifiedVehicleState::from_operator_trusted(state))
}

// ── Decision comparison ───────────────────────────────────────────────────────

fn parse_expected_decision(s: &str) -> Decision {
    match s {
        "ALLOW" => Decision::Allow,
        "DENY" => Decision::Deny,
        "EXPIRED" => Decision::Expired,
        "PENDING_APPROVAL" => Decision::PendingApproval,
        other => panic!("unknown expected verdict: {other}"),
    }
}

// ── Gateway test harness ──────────────────────────────────────────────────────

struct GatewayHandle {
    demo_keys: a2g_gateway::keys::DemoKeys,
    socket_path: PathBuf,
    _tmp: TempDir,
    shutdown_tx: mpsc::Sender<()>,
}

impl GatewayHandle {
    fn start() -> Self {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("gateway.sock");
        let key_path = tmp.path().join("demo-keys.json");

        let (keys, demo_keys) = generate(&key_path);
        let state = Arc::new(GatewayState::new(keys, demo_keys.clone(), "vcan0"));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let state_clone = Arc::clone(&state);
        let socket_clone = socket_path.clone();
        std::thread::spawn(move || {
            serve(state_clone, &socket_clone, ready_tx, shutdown_rx);
        });
        ready_rx.recv().expect("gateway ready");

        GatewayHandle {
            demo_keys,
            socket_path,
            _tmp: tmp,
            shutdown_tx,
        }
    }

    fn send(&self, req: &GatewayRequest) -> GatewayResponse {
        send_request(&self.socket_path, req)
    }

    fn receipt_signing_key(&self) -> SigningKey {
        self.demo_keys.receipt_signing_key()
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ── Core vector runner ────────────────────────────────────────────────────────

fn run_vector(v: &TestVector) -> Outcome {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_vector_inner(v)));
    match result {
        Ok(outcome) => outcome,
        Err(_) => Outcome::Fail("runner panicked".to_string()),
    }
}

fn run_vector_inner(v: &TestVector) -> Outcome {
    let input = &v.input;

    // ── Build mandate ──────────────────────────────────────────────────────────
    let mandate_str = if input.mandate_use_spec_signing {
        build_spec_signed_mandate(input)
    } else {
        let (signed, _) = build_mandate(input);
        if input.mandate_bad_signature {
            tamper_signature(&signed)
        } else {
            signed
        }
    };

    // ── Vehicle state ──────────────────────────────────────────────────────────
    let vehicle_state = build_vehicle_state(input);

    // ── Clock ──────────────────────────────────────────────────────────────────
    let now = Utc::now() + Duration::seconds(input.clock_offset_seconds);

    // ── Gateway test path ──────────────────────────────────────────────────────
    if let Some(gw_test) = &input.gateway_test_type {
        return run_gateway_vector(v, &mandate_str, vehicle_state.as_ref(), now, gw_test);
    }

    // ── Phase 2 test path ──────────────────────────────────────────────────────
    if let Some(grant_type) = &input.phase2_grant_type {
        return run_phase2_vector(v, &mandate_str, vehicle_state.as_ref(), now, grant_type);
    }

    // ── Standard decide() path ────────────────────────────────────────────────
    let params = &input.params;
    let verdict = match decide(
        &mandate_str,
        &input.capability,
        params,
        &NoopLedger,
        now,
        vehicle_state.as_ref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let fail_reason = format!("decide() returned error: {e}");
            return if v.known_failing {
                Outcome::KnownFail(fail_reason)
            } else {
                Outcome::Fail(fail_reason)
            };
        }
    };

    check_verdict(v, &verdict.decision, &verdict.policy_rule)
}

fn run_phase2_vector(
    v: &TestVector,
    mandate_str: &str,
    vehicle_state: Option<&VerifiedVehicleState>,
    now: chrono::DateTime<Utc>,
    grant_type: &str,
) -> Outcome {
    let input = &v.input;
    let params = &input.params;

    // Phase 1: must produce PendingApproval
    let phase1 = match decide(
        mandate_str,
        &input.capability,
        params,
        &NoopLedger,
        now,
        vehicle_state,
    ) {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("Phase 1 decide() error: {e}");
            return if v.known_failing {
                Outcome::KnownFail(reason)
            } else {
                Outcome::Fail(reason)
            };
        }
    };

    // For Phase 2 tests (except forbidden+grant which denies at Phase 1 as Forbidden),
    // Phase 1 should produce PendingApproval OR Deny for forbidden.
    // ff-006 (forbidden + Phase 2) expects DENY from Phase 1 directly.
    if phase1.decision == Decision::Deny {
        // Forbidden pre-check fired in Phase 1; no Phase 2 needed.
        return check_verdict(v, &phase1.decision, &phase1.policy_rule);
    }

    let binding = match phase1.pending_approval {
        Some(ref b) => b.clone(),
        None => {
            let reason = format!(
                "Phase 1 returned {:?} but expected PendingApproval",
                phase1.decision
            );
            return if v.known_failing {
                Outcome::KnownFail(reason)
            } else {
                Outcome::Fail(reason)
            };
        }
    };

    // If the expected verdict is PENDING_APPROVAL, we're done after Phase 1.
    if v.expected.verdict == "PENDING_APPROVAL" {
        return check_verdict(v, &phase1.decision, &phase1.policy_rule);
    }

    // Build the ApprovalGrant based on grant_type.
    let (_, approver_secret, _) = generate_agent_keypair();
    let approver_secret_bytes = hex::decode(&approver_secret).unwrap();
    let approver_secret_arr: [u8; 32] = approver_secret_bytes.as_slice().try_into().unwrap();
    let approver_key = SigningKey::from_bytes(&approver_secret_arr);
    let approver_did = "did:a2g:conformance-approver".to_string();

    let phase1_receipt_hash = "0".repeat(64); // simulated receipt hash

    let grant = match grant_type {
        "valid" => ApprovalGrant::new_signed(
            &binding.binding_id,
            &binding.request_hash,
            &approver_did,
            &approver_key,
            300,
            now,
            &phase1_receipt_hash,
        ),
        "mismatched_hash" => ApprovalGrant::new_signed(
            &binding.binding_id,
            &hex::encode(Sha256::digest(b"wrong_request")), // wrong request_hash
            &approver_did,
            &approver_key,
            300,
            now,
            &phase1_receipt_hash,
        ),
        "expired" => {
            // Grant that expired 1 hour ago
            let past = now - Duration::hours(2);
            ApprovalGrant::new_signed(
                &binding.binding_id,
                &binding.request_hash,
                &approver_did,
                &approver_key,
                1,    // ttl_seconds = 1 second
                past, // issued in the past so already expired
                &phase1_receipt_hash,
            )
        }
        "wrong_binding_id" => ApprovalGrant::new_signed(
            &uuid::Uuid::new_v4().to_string(), // wrong binding_id
            &binding.request_hash,
            &approver_did,
            &approver_key,
            300,
            now,
            &phase1_receipt_hash,
        ),
        "bad_signature" => {
            let mut grant = ApprovalGrant::new_signed(
                &binding.binding_id,
                &binding.request_hash,
                &approver_did,
                &approver_key,
                300,
                now,
                &phase1_receipt_hash,
            );
            // Corrupt the signature
            grant.signature = "00".repeat(64);
            grant
        }
        other => {
            return Outcome::Fail(format!("unknown phase2_grant_type: {other}"));
        }
    };

    let phase2 = match decide_with_approval(
        mandate_str,
        &input.capability,
        params,
        &NoopLedger,
        now,
        vehicle_state,
        &binding,
        &grant,
    ) {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("Phase 2 decide_with_approval() error: {e}");
            return if v.known_failing {
                Outcome::KnownFail(reason)
            } else {
                Outcome::Fail(reason)
            };
        }
    };

    // tp-008: additionally verify parent_receipt_hash is set on ALLOW verdict
    if v.id == "tp-008"
        && phase2.decision == Decision::Allow
        && phase2.parent_receipt_hash.is_empty()
    {
        let reason = "tp-008: Phase 2 ALLOW verdict missing parent_receipt_hash".to_string();
        return if v.known_failing {
            Outcome::KnownFail(reason)
        } else {
            Outcome::Fail(reason)
        };
    }

    check_verdict(v, &phase2.decision, &phase2.policy_rule)
}

fn run_gateway_vector(
    v: &TestVector,
    mandate_str: &str,
    vehicle_state: Option<&VerifiedVehicleState>,
    now: chrono::DateTime<Utc>,
    gw_test: &str,
) -> Outcome {
    let input = &v.input;
    let params = &input.params;
    let params_json = serde_json::to_string(params).unwrap_or_default();

    let gw = GatewayHandle::start();
    let signing_key = gw.receipt_signing_key();

    match gw_test {
        "enforce" => {
            // Standard ALLOW path: run decide(), sign the receipt, send to gateway
            let verdict = match decide(
                mandate_str,
                &input.capability,
                params,
                &NoopLedger,
                now,
                vehicle_state,
            ) {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("decide() error: {e}");
                    return if v.known_failing {
                        Outcome::KnownFail(reason)
                    } else {
                        Outcome::Fail(reason)
                    };
                }
            };

            if verdict.decision != Decision::Allow {
                let reason = format!(
                    "gc enforce: expected ALLOW from decide() but got {:?}",
                    verdict.decision
                );
                return if v.known_failing {
                    Outcome::KnownFail(reason)
                } else {
                    Outcome::Fail(reason)
                };
            }

            let receipt = sign_receipt_with_params(&verdict, &params_json, "", &signing_key, None);
            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });

            match resp {
                GatewayResponse::Enforced { .. } => check_gateway_outcome(v, true, None),
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                other => {
                    let reason = format!("unexpected gateway response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(reason)
                    } else {
                        Outcome::Fail(reason)
                    }
                }
            }
        }

        "forbidden_receipt" => {
            // Construct a receipt for a forbidden tool, claiming ALLOW (which the rich domain
            // would never produce, but the gateway must re-check regardless).
            let fake_verdict_id = uuid::Uuid::new_v4().to_string();
            let issued_at_ms = Utc::now().timestamp_millis();
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(nonce);
            let request_hash = a2g_gateway::protocol::GatewayReceipt::compute_request_hash(
                &input.capability,
                &params_json,
                issued_at_ms,
            );
            let receipt_partial = GatewayReceipt {
                verdict_id: fake_verdict_id,
                decision: "ALLOW".to_string(),
                tool: input.capability.clone(),
                params_json: params_json.clone(),
                policy_rule: "all_checks_passed".to_string(),
                state_trust: "none".to_string(),
                binding_id: String::new(),
                request_hash,
                issued_at_ms,
                nonce_hex,
                signature_hex: String::new(),
                attested_state_json: None,
            };
            let payload = receipt_partial.canonical_payload();
            let sig: ed25519_dalek::Signature = signing_key.sign(payload.as_bytes());
            let receipt = GatewayReceipt {
                signature_hex: hex::encode(sig.to_bytes()),
                ..receipt_partial
            };

            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r = "gateway allowed forbidden tool — step 1 forbidden re-check failed"
                        .to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        "replay" => {
            // Send the same receipt twice — second must be refused with nonce error.
            let verdict = match decide(
                mandate_str,
                &input.capability,
                params,
                &NoopLedger,
                now,
                vehicle_state,
            ) {
                Ok(v) => v,
                Err(e) => return Outcome::Fail(format!("decide() error: {e}")),
            };
            let receipt = sign_receipt_with_params(&verdict, &params_json, "", &signing_key, None);
            let receipt2 = receipt.clone();

            // First send should succeed
            gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });
            // Second send is the replay
            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt2),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r =
                        "gateway allowed replayed receipt — step 5 nonce check failed".to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        "stale" => {
            // Receipt with issued_at_ms far in the past — freshness check should refuse.
            let verdict = match decide(
                mandate_str,
                &input.capability,
                params,
                &NoopLedger,
                now,
                vehicle_state,
            ) {
                Ok(v) => v,
                Err(e) => return Outcome::Fail(format!("decide() error: {e}")),
            };

            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(nonce);

            // issued_at_ms is 30 seconds ago (well outside ±2s window)
            let stale_issued_at_ms = Utc::now().timestamp_millis() - 30_000;
            let request_hash = GatewayReceipt::compute_request_hash(
                &verdict.tool,
                &params_json,
                stale_issued_at_ms,
            );
            let receipt_partial = GatewayReceipt {
                verdict_id: verdict.verdict_id.clone(),
                decision: "ALLOW".to_string(),
                tool: verdict.tool.clone(),
                params_json: params_json.clone(),
                policy_rule: verdict.policy_rule.clone(),
                state_trust: verdict.state_trust.clone(),
                binding_id: String::new(),
                request_hash,
                issued_at_ms: stale_issued_at_ms,
                nonce_hex,
                signature_hex: String::new(),
                attested_state_json: None,
            };
            let payload = receipt_partial.canonical_payload();
            let sig: ed25519_dalek::Signature = signing_key.sign(payload.as_bytes());
            let receipt = GatewayReceipt {
                signature_hex: hex::encode(sig.to_bytes()),
                ..receipt_partial
            };

            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r =
                        "gateway allowed stale receipt — step 4 freshness check failed".to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        "deny_receipt" => {
            // Receipt with decision="DENY" — gateway step 3 must refuse.
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(nonce);
            let issued_at_ms = Utc::now().timestamp_millis();
            let request_hash =
                GatewayReceipt::compute_request_hash(&input.capability, &params_json, issued_at_ms);
            let receipt_partial = GatewayReceipt {
                verdict_id: uuid::Uuid::new_v4().to_string(),
                decision: "DENY".to_string(), // wrong — must be refused at step 3
                tool: input.capability.clone(),
                params_json: params_json.clone(),
                policy_rule: "test_deny".to_string(),
                state_trust: "none".to_string(),
                binding_id: String::new(),
                request_hash,
                issued_at_ms,
                nonce_hex,
                signature_hex: String::new(),
                attested_state_json: None,
            };
            let payload = receipt_partial.canonical_payload();
            let sig: ed25519_dalek::Signature = signing_key.sign(payload.as_bytes());
            let receipt = GatewayReceipt {
                signature_hex: hex::encode(sig.to_bytes()),
                ..receipt_partial
            };
            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r = "gateway allowed DENY receipt — step 3 check failed".to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        "tampered_tool" => {
            // Receipt is signed with params_json P, but params_json is mutated to P' after
            // signing. The canonical payload (which covers request_hash) still validates
            // (step 2 passes), but step 6 recomputes request_hash from the mutated params_json
            // and finds a mismatch → Refused at step 6.
            //
            // Mutating tool would fail at step 2 (tool is in the canonical payload);
            // mutating params_json does not affect the canonical signature but does affect
            // the request_hash recomputation, which is exactly what step 6 checks.
            let verdict = match decide(
                mandate_str,
                &input.capability,
                params,
                &NoopLedger,
                now,
                vehicle_state,
            ) {
                Ok(v) => v,
                Err(e) => return Outcome::Fail(format!("decide() error: {e}")),
            };
            let original_receipt =
                sign_receipt_with_params(&verdict, &params_json, "", &signing_key, None);
            // Mutate params_json after signing — signature still valid but request_hash
            // recomputation will mismatch → step 6 Refused.
            let tampered_receipt = GatewayReceipt {
                params_json: r#"{"tampered":true}"#.to_string(),
                ..original_receipt
            };
            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(tampered_receipt),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r =
                        "gateway allowed tampered-tool receipt — step 6 request_hash check failed"
                            .to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        "no_binding" => {
            // Phase 1 returns PENDING_APPROVAL; we send a Phase 2 Enforce receipt without
            // ever calling SignBinding / SubmitGrant, so step 7 must refuse.
            let phase1 = match decide(
                mandate_str,
                &input.capability,
                params,
                &NoopLedger,
                now,
                vehicle_state,
            ) {
                Ok(v) => v,
                Err(e) => return Outcome::Fail(format!("decide() error: {e}")),
            };

            if phase1.decision != Decision::PendingApproval {
                let r = format!(
                    "gc no_binding: expected PendingApproval, got {:?}",
                    phase1.decision
                );
                return if v.known_failing {
                    Outcome::KnownFail(r)
                } else {
                    Outcome::Fail(r)
                };
            }

            // Synthesize a Phase 2 Enforce receipt with a fabricated binding_id
            let fake_binding_id = uuid::Uuid::new_v4().to_string();
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(nonce);
            let issued_at_ms = Utc::now().timestamp_millis();
            let request_hash =
                GatewayReceipt::compute_request_hash(&input.capability, &params_json, issued_at_ms);
            let receipt_partial = GatewayReceipt {
                verdict_id: uuid::Uuid::new_v4().to_string(),
                decision: "ALLOW".to_string(),
                tool: input.capability.clone(),
                params_json: params_json.clone(),
                policy_rule: "all_checks_passed".to_string(),
                state_trust: "operator_trusted".to_string(),
                binding_id: fake_binding_id,
                request_hash,
                issued_at_ms,
                nonce_hex,
                signature_hex: String::new(),
                attested_state_json: None,
            };
            let payload = receipt_partial.canonical_payload();
            let sig: ed25519_dalek::Signature = signing_key.sign(payload.as_bytes());
            let receipt = GatewayReceipt {
                signature_hex: hex::encode(sig.to_bytes()),
                ..receipt_partial
            };

            // Phase 1 verdict for the "verdict" check
            let resp = gw.send(&GatewayRequest::Enforce {
                receipt: Box::new(receipt),
            });
            match resp {
                GatewayResponse::Refused { reason } => {
                    // The expected verdict here reflects the Phase 1 verdict (PENDING_APPROVAL),
                    // not the gateway response verdict.
                    check_gateway_outcome(v, false, Some(&reason))
                }
                GatewayResponse::Enforced { .. } => {
                    let r = "gateway allowed Phase 2 without approved binding — step 7 failed"
                        .to_string();
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
                other => {
                    let r = format!("unexpected response: {other:?}");
                    if v.known_failing {
                        Outcome::KnownFail(r)
                    } else {
                        Outcome::Fail(r)
                    }
                }
            }
        }

        other => Outcome::Fail(format!("unknown gateway_test_type: {other}")),
    }
}

// ── Result checkers ───────────────────────────────────────────────────────────

fn check_verdict(v: &TestVector, actual_decision: &Decision, actual_policy: &str) -> Outcome {
    let expected_decision = parse_expected_decision(&v.expected.verdict);

    if *actual_decision != expected_decision {
        let reason = format!(
            "verdict mismatch: expected {:?} but got {:?} (policy_rule='{}')",
            expected_decision, actual_decision, actual_policy
        );
        return if v.known_failing {
            Outcome::KnownFail(reason)
        } else {
            Outcome::Fail(reason)
        };
    }

    if let Some(ref needle) = v.expected.policy_rule_contains {
        if !actual_policy.contains(needle.as_str()) {
            let reason = format!(
                "policy_rule '{}' does not contain expected substring '{}'",
                actual_policy, needle
            );
            return if v.known_failing {
                Outcome::KnownFail(reason)
            } else {
                Outcome::Fail(reason)
            };
        }
    }

    if v.known_failing {
        Outcome::KnownFail("known_failing but actually passed".to_string())
    } else {
        Outcome::Pass
    }
}

fn check_gateway_outcome(v: &TestVector, enforced: bool, refused_reason: Option<&str>) -> Outcome {
    // Check gateway_enforced expectation
    if let Some(expected_enforced) = v.expected.gateway_enforced {
        if enforced != expected_enforced {
            let reason = format!(
                "gateway_enforced: expected {} but got {}",
                expected_enforced, enforced
            );
            return if v.known_failing {
                Outcome::KnownFail(reason)
            } else {
                Outcome::Fail(reason)
            };
        }
    }

    // Check refused reason substring
    if let Some(ref needle) = v.expected.gateway_refused_reason_contains {
        match refused_reason {
            Some(r) if r.to_lowercase().contains(needle.to_lowercase().as_str()) => {}
            Some(r) => {
                let reason = format!(
                    "refused reason '{}' does not contain expected substring '{}'",
                    r, needle
                );
                return if v.known_failing {
                    Outcome::KnownFail(reason)
                } else {
                    Outcome::Fail(reason)
                };
            }
            None => {
                let reason = format!(
                    "expected gateway Refused with '{}' but got Enforced",
                    needle
                );
                return if v.known_failing {
                    Outcome::KnownFail(reason)
                } else {
                    Outcome::Fail(reason)
                };
            }
        }
    }

    if v.known_failing {
        Outcome::KnownFail("known_failing but actually passed".to_string())
    } else {
        Outcome::Pass
    }
}

// ── Vector loader ─────────────────────────────────────────────────────────────

fn load_vectors(vectors_dir: &Path) -> Vec<(String, TestVector)> {
    let mut all: Vec<(String, TestVector)> = Vec::new();

    for entry in std::fs::read_dir(vectors_dir).expect("read vectors dir") {
        let entry = entry.expect("dir entry");
        let cat_path = entry.path();
        if !cat_path.is_dir() {
            continue;
        }
        let mut files: Vec<_> = std::fs::read_dir(&cat_path)
            .expect("read category dir")
            .map(|e| e.expect("file entry").path())
            .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
            .collect();
        files.sort();
        for file in files {
            let content = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {}", file.display(), e));
            let vector: TestVector = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("parse {}: {}", file.display(), e));
            let display = file.display().to_string();
            all.push((display, vector));
        }
    }

    all
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // Locate the vectors directory relative to the workspace root.
    // When run via `cargo run -p a2g-conformance`, cwd is the workspace root.
    // Allow override via env var for CI flexibility.
    let vectors_dir = std::env::var("A2G_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("conformance/vectors"));

    if !vectors_dir.exists() {
        eprintln!(
            "Error: vectors directory not found at '{}'. \
             Set A2G_VECTORS_DIR env var or run from workspace root.",
            vectors_dir.display()
        );
        std::process::exit(1);
    }

    let vectors = load_vectors(&vectors_dir);

    if vectors.is_empty() {
        eprintln!("No vectors found in '{}'", vectors_dir.display());
        std::process::exit(1);
    }

    println!("A2G Protocol Conformance Suite — {} vectors", vectors.len());
    println!("{}", "─".repeat(72));

    let mut pass = 0usize;
    let mut known_fail = 0usize;
    let mut unexpected_fail = 0usize;

    for (path, v) in &vectors {
        let outcome = run_vector(v);

        let tag = match &outcome {
            Outcome::Pass => "PASS",
            Outcome::KnownFail(_) => "KNOWN_FAIL",
            Outcome::Fail(_) => "FAIL",
        };

        let spec = &v.spec_ref;
        let id = &v.id;
        let desc = &v.description;

        match &outcome {
            Outcome::Pass => {
                pass += 1;
                println!("[{tag:10}] {id} ({spec}) {desc}");
            }
            Outcome::KnownFail(r) => {
                known_fail += 1;
                println!("[{tag:10}] {id} ({spec}) {desc}");
                println!("             reason: {r}");
            }
            Outcome::Fail(r) => {
                unexpected_fail += 1;
                println!("[{tag:10}] {id} ({spec}) {desc}");
                println!("             reason: {r}");
                println!("             file:   {path}");
            }
        }
    }

    println!("{}", "─".repeat(72));
    println!(
        "Results: {} passed, {} known_fail, {} unexpected failures (total: {})",
        pass,
        known_fail,
        unexpected_fail,
        vectors.len()
    );

    if unexpected_fail > 0 {
        println!(
            "\n{} unexpected failure(s) — reference implementation diverges from SPEC.md.",
            unexpected_fail
        );
        println!("See CONFORMANCE.md §Known Divergences for guidance.");
        std::process::exit(1);
    } else {
        println!("\nAll non-known-failing vectors passed. Reference implementation is conformant.");
    }
}
