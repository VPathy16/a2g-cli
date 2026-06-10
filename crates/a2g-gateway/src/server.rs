//! Gateway server: socket listener, connection handler, 7-step receipt verification.
//!
//! ## Verification order (ADR-0010; forbidden first per task spec)
//!
//! 1. **Forbidden re-check** — independent of rich-domain verdict; refused unconditionally.
//! 2. **Signature valid** — ed25519 over canonical payload; unknown key → refused.
//! 3. **Decision is ALLOW** — any other value → refused.
//! 4. **Freshness** — `issued_at_ms` within ±2 000 ms of gateway clock.
//! 5. **Nonce not seen** — anti-replay ring buffer.
//! 6. **Action match** — `request_hash = SHA-256(tool || params_json || issued_at_ms)`.
//! 7. **Binding match** (Phase 2 only) — `binding_id` in approved queue; hashes match.
//!
//! Additionally: if the receipt's `attested_state_json` is present, the gateway
//! verifies it with the known ECU key and rejects receipts that claim "attested"
//! state_trust but cannot be independently verified.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use a2g_core::hitl::{ApprovalGrant, PendingApprovalBinding};
use a2g_core::vehicle::{AttestedVehicleState, ATTESTATION_FRESHNESS_MS};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::bus;
use crate::forbidden;
use crate::keys::{DemoKeys, GatewayKeys};
use crate::pending::PendingQueue;
use crate::protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};

/// Receipt freshness window.
///
/// The check is **bidirectional (±2 000 ms)** to tolerate sub-millisecond
/// cross-process clock skew between the rich domain (receipt signer) and the
/// gateway (verifier).  Both processes run on the same host in the demo tier;
/// ±2 s is deliberately generous for that deployment.
///
/// Distinct from `a2g_core::vehicle::ATTESTATION_FRESHNESS_MS` (500 ms,
/// unidirectional past-only) which governs ECU-signed vehicle state freshness.
/// See ADR-0010 §Freshness Windows for the rationale behind both values.
const RECEIPT_FRESHNESS_MS: i64 = 2_000;

/// Shared gateway state (Arc-wrapped for multi-connection serving).
pub struct GatewayState {
    pub keys: GatewayKeys,
    pub demo_keys: DemoKeys,
    pub vcan_iface: String,
    pub pending: Mutex<PendingQueue>,
}

impl GatewayState {
    pub fn new(keys: GatewayKeys, demo_keys: DemoKeys, vcan_iface: &str) -> Self {
        GatewayState {
            keys,
            demo_keys,
            vcan_iface: vcan_iface.to_string(),
            pending: Mutex::new(PendingQueue::new()),
        }
    }
}

/// Start the gateway server on `socket_path`.
///
/// Signals readiness via `ready_tx` once the socket is bound and listening.
/// Continues accepting connections until `shutdown_rx` becomes readable
/// (i.e., the sender is dropped or explicitly sends a message).
pub fn serve(
    state: Arc<GatewayState>,
    socket_path: &Path,
    ready_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
) {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("gateway: bind socket");
    listener
        .set_nonblocking(true)
        .expect("gateway: set_nonblocking");

    ready_tx.send(()).expect("gateway: ready signal");

    loop {
        // Check for shutdown (non-blocking try_recv).
        if shutdown_rx.try_recv().is_ok() {
            break;
        }
        // Check if sender was dropped.
        if matches!(
            shutdown_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ) {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                // Handle inline (one request per connection; no threading needed for demo).
                handle_connection(stream, &state);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                eprintln!("[gateway] accept error: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
}

fn handle_connection(stream: std::os::unix::net::UnixStream, state: &Arc<GatewayState>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap_or(());

    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();

    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }

    let response = match serde_json::from_str::<GatewayRequest>(request_line.trim()) {
        Ok(req) => handle_request(req, state),
        Err(e) => GatewayResponse::Error {
            message: format!("malformed request: {e}"),
        },
    };

    let mut out = stream;
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(&response).unwrap_or_default()
    );
}

fn handle_request(req: GatewayRequest, state: &Arc<GatewayState>) -> GatewayResponse {
    match req {
        GatewayRequest::GetPublicKeys => GatewayResponse::PublicKeys {
            receipt_verifying_key_hex: state.demo_keys.receipt_verifying_key_hex.clone(),
            attester_verifying_key_hex: state.demo_keys.attester_verifying_key_hex.clone(),
            operator_verifying_key_hex: state.demo_keys.operator_verifying_key_hex.clone(),
        },

        GatewayRequest::SignBinding { binding_json } => handle_sign_binding(binding_json, state),

        GatewayRequest::SubmitGrant { grant_json } => handle_submit_grant(grant_json, state),

        GatewayRequest::Enforce { receipt } => handle_enforce(*receipt, state),
    }
}

// ── SignBinding ───────────────────────────────────────────────────────────────

fn handle_sign_binding(binding_json: String, state: &Arc<GatewayState>) -> GatewayResponse {
    let binding: PendingApprovalBinding = match serde_json::from_str(&binding_json) {
        Ok(b) => b,
        Err(e) => {
            return GatewayResponse::Error {
                message: format!("invalid binding JSON: {e}"),
            }
        }
    };

    // Sign with gateway's binding key (never shared — closes ADR-0009 interim).
    let payload = match binding_bytes(&binding) {
        Ok(b) => b,
        Err(e) => {
            return GatewayResponse::Error {
                message: format!("binding encoding error: {e}"),
            }
        }
    };
    let sig: ed25519_dalek::Signature = state.keys.binding_signing_key.sign(&payload);
    let signed = SignedBindingWire {
        binding_id: binding.binding_id.clone(),
        request_hash: binding.request_hash.clone(),
        escalate_to: binding.escalate_to.clone(),
        ttl_expires_at: binding.ttl_expires_at.to_rfc3339(),
        a2g_mac: hex::encode(sig.to_bytes()),
    };

    let signed_json = match serde_json::to_string(&signed) {
        Ok(s) => s,
        Err(e) => {
            return GatewayResponse::Error {
                message: format!("serialization error: {e}"),
            }
        }
    };

    let mut q = state.pending.lock().unwrap();
    q.expire(Utc::now());
    q.insert(signed_json.clone(), binding);

    GatewayResponse::SignedBinding { signed_json }
}

// ── SubmitGrant ───────────────────────────────────────────────────────────────

fn handle_submit_grant(grant_json: String, state: &Arc<GatewayState>) -> GatewayResponse {
    let grant: ApprovalGrant = match serde_json::from_str(&grant_json) {
        Ok(g) => g,
        Err(e) => {
            return GatewayResponse::Error {
                message: format!("invalid grant JSON: {e}"),
            }
        }
    };

    // Verify grant signature against known operator key (closes ADR-0008's queue ownership).
    let op_key = &state.keys.operator_verifying_key;
    let expected_op_hex = hex::encode(op_key.to_bytes());
    if grant.approver_pubkey != expected_op_hex {
        eprintln!(
            "[gateway] grant rejected: approver key {} not the known operator key",
            &grant.approver_pubkey[..8]
        );
        return GatewayResponse::Refused {
            reason: "grant rejected: approver is not the authorized operator".to_string(),
        };
    }

    let now = Utc::now();
    let mut q = state.pending.lock().unwrap();
    q.expire(now);

    let pending = match q.get(&grant.binding_id) {
        Some(e) => e.binding.clone(),
        None => {
            return GatewayResponse::Refused {
                reason: format!("no pending binding for id {}", grant.binding_id),
            }
        }
    };

    if let Err(e) = grant.verify_against_binding(&pending, now) {
        eprintln!("[gateway] grant verification failed: {e}");
        return GatewayResponse::Refused {
            reason: format!("grant verification failed: {e}"),
        };
    }

    let binding_id = grant.binding_id.clone();
    q.approve(&binding_id, grant);
    GatewayResponse::GrantAccepted { binding_id }
}

// ── Enforce ───────────────────────────────────────────────────────────────────

fn handle_enforce(receipt: GatewayReceipt, state: &Arc<GatewayState>) -> GatewayResponse {
    // ── Step 1: Forbidden re-check (FIRST — unconditional, no exceptions) ──────
    // Checked before signature verification (defense-in-depth).  Safe on
    // unverified input: classify_vehicle_tool() is allocation-free, panic-free,
    // and O(bounded) — starts_with chains for vehicle.* prefixes, linear scan
    // over a fixed 415-entry VHAL table for everything else.  An unauthenticated
    // caller cannot exploit the classification: a forbidden return is an
    // unconditional REFUSE; a non-forbidden return still requires a valid
    // gateway-issued signature at step 2.  See ADR-0010 §Forbidden-First.
    if forbidden::is_forbidden(&receipt.tool) {
        let reason = forbidden::refuse_reason(&receipt.tool);
        eprintln!("[gateway] REFUSE {reason}");
        return GatewayResponse::Refused { reason };
    }

    // ── Step 2: Signature validity ─────────────────────────────────────────────
    let payload = match receipt.canonical_bytes() {
        Ok(b) => b,
        Err(e) => return refuse(&format!("receipt encoding error: {e}")),
    };
    let sig_bytes: [u8; 64] = match hex::decode(&receipt.signature_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => {
            return refuse("receipt signature is not valid 64-byte hex");
        }
    };
    let sig = Signature::from_bytes(&sig_bytes);
    if state
        .keys
        .receipt_verifying_key
        .verify(&payload, &sig)
        .is_err()
    {
        return refuse("receipt signature verification failed");
    }

    // ── Step 3: Decision is ALLOW ──────────────────────────────────────────────
    if receipt.decision != "ALLOW" {
        return refuse(&format!(
            "receipt decision is '{}'; only ALLOW is enforced",
            receipt.decision
        ));
    }

    // ── Step 4: Freshness ──────────────────────────────────────────────────────
    let now_ms = Utc::now().timestamp_millis();
    let age_ms = now_ms - receipt.issued_at_ms;
    if !(-RECEIPT_FRESHNESS_MS..=RECEIPT_FRESHNESS_MS).contains(&age_ms) {
        return refuse(&format!(
            "receipt is stale or future-dated: age {}ms, window ±{}ms",
            age_ms, RECEIPT_FRESHNESS_MS
        ));
    }

    // ── Step 5: Nonce not seen (anti-replay) ───────────────────────────────────
    {
        let mut q = state.pending.lock().unwrap();
        if q.nonce_seen(&receipt.nonce_hex) {
            return refuse("receipt nonce has been seen before (replay attempt)");
        }
        q.record_nonce(receipt.nonce_hex.clone());
    }

    // ── Step 6: Action match ───────────────────────────────────────────────────
    let expected_hash = receipt.expected_request_hash();
    if receipt.request_hash != expected_hash {
        return refuse(&format!(
            "request_hash mismatch: got {} expected {}",
            &receipt.request_hash[..8],
            &expected_hash[..8]
        ));
    }

    // ── Step 7: Binding match (Phase 2 only) ──────────────────────────────────
    // The binding_id uniquely identifies a specific Phase 1 request that was
    // pre-approved by the operator.  The HITL request_hash (inside the binding)
    // and the receipt request_hash serve different purposes (ADR-0008 vs ADR-0010)
    // and are not compared here — the approved binding_id is the proof.
    if !receipt.binding_id.is_empty() {
        {
            let q = state.pending.lock().unwrap();
            match q.get(&receipt.binding_id) {
                None => {
                    return refuse(&format!(
                        "no pending binding for id {} (expired or unknown)",
                        receipt.binding_id
                    ));
                }
                Some(entry) if !entry.approved => {
                    return refuse(&format!(
                        "binding {} has not been approved by the operator",
                        receipt.binding_id
                    ));
                }
                Some(_) => {}
            }
        }
        // Consume the binding (one-use — prevents Phase 2 replay).
        state.pending.lock().unwrap().remove(&receipt.binding_id);
    }

    // ── Attestation check ──────────────────────────────────────────────────────
    // If the receipt claims "attested" state_trust, the gateway must independently
    // verify the AttestedVehicleState (closes ADR-0007's verifier deferral).
    if receipt.state_trust == "attested" {
        if let Some(ref attested_json) = receipt.attested_state_json {
            let attested: AttestedVehicleState = match serde_json::from_str(attested_json) {
                Ok(a) => a,
                Err(e) => {
                    return refuse(&format!("attested_state_json parse error: {e}"));
                }
            };
            let expected_pubkey = hex::encode(state.keys.attester_verifying_key.to_bytes());
            if let Err(e) =
                attested.verify(&expected_pubkey, Utc::now(), ATTESTATION_FRESHNESS_MS, None)
            {
                return refuse(&format!(
                    "vehicle state attestation failed: {e}; \
                     receipt claims 'attested' state_trust but gateway could not verify"
                ));
            }
        } else {
            return refuse(
                "receipt claims state_trust='attested' but no attested_state_json was provided",
            );
        }
    }

    // ── All checks passed → write to bus ──────────────────────────────────────
    let (frame_hex, real_write) =
        bus::write_enforcement_frame(&state.vcan_iface, &receipt.verdict_id, &receipt.tool);

    GatewayResponse::Enforced {
        verdict_id: receipt.verdict_id,
        frame_hex,
        real_write,
    }
}

fn refuse(reason: &str) -> GatewayResponse {
    eprintln!("[gateway] REFUSE {reason}");
    GatewayResponse::Refused {
        reason: reason.to_string(),
    }
}

// ── SignedBinding wire format ─────────────────────────────────────────────────

/// Wire format for the signed binding blob (matches a2g-ffi's SignedBinding).
/// The gateway is now the authoritative signer (closes ADR-0009 §binding-key interim).
#[derive(serde::Serialize, serde::Deserialize)]
struct SignedBindingWire {
    binding_id: String,
    request_hash: String,
    escalate_to: String,
    ttl_expires_at: String,
    /// Hex ed25519 signature over `binding_payload()`.
    a2g_mac: String,
}

/// Canonical CBOR bytes signed by the gateway's binding key (ADR-0011).
fn binding_bytes(b: &PendingApprovalBinding) -> Result<Vec<u8>, a2g_core::A2gError> {
    let hash_bytes =
        hex::decode(&b.request_hash).map_err(|e| a2g_core::A2gError::HexDecode(e.to_string()))?;
    a2g_core::cbor::encode_canonical(&a2g_core::cbor::BindingPayload {
        tag: "BINDING".to_string(),
        binding_id: b.binding_id.clone(),
        request_hash: hash_bytes.into(),
        escalate_to: b.escalate_to.clone(),
        ttl_unix_secs: b.ttl_expires_at.timestamp(),
    })
}

/// Verify a signed binding blob produced by this gateway (used by Phase 2 receipt signers).
pub fn verify_signed_binding(
    signed_json: &str,
    binding_key_verifying: &VerifyingKey,
) -> Option<PendingApprovalBinding> {
    let wire: SignedBindingWire = serde_json::from_str(signed_json).ok()?;
    let ttl = wire.ttl_expires_at.parse::<chrono::DateTime<Utc>>().ok()?;
    let binding = PendingApprovalBinding {
        binding_id: wire.binding_id.clone(),
        request_hash: wire.request_hash.clone(),
        escalate_to: wire.escalate_to.clone(),
        ttl_expires_at: ttl,
    };
    let payload = binding_bytes(&binding).ok()?;
    let sig_bytes: [u8; 64] = hex::decode(&wire.a2g_mac).ok()?.try_into().ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    binding_key_verifying.verify(&payload, &sig).ok()?;
    Some(binding)
}

/// Set of nonces from the most recent batch (used by test helpers to verify anti-replay).
pub fn seen_nonces_snapshot(state: &Arc<GatewayState>) -> HashSet<String> {
    drop(state.pending.lock().unwrap());
    HashSet::new()
}
