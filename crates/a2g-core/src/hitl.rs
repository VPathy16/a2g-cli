//! Human-in-the-Loop types — ADR-0008 two-phase approval contract.
//!
//! ## Phase 1 — `decide()` returns `PendingApproval`
//!
//! When a tool is in `escalate_tools`, `decide()` returns immediately with
//! `Decision::PendingApproval` and a [`PendingApprovalBinding`] carrying:
//!
//! - **`binding_id`** — UUID identifying this specific pending request.
//! - **`request_hash`** — SHA-256 over `"REQUEST:<mandate_hash>:<tool>:<params_hash>:<timestamp>"`.
//!   Binds the approval to the exact action; a different action yields a different hash.
//! - **`escalate_to`** — DID of the required approver, from the mandate.
//! - **`ttl_expires_at`** — deadline after which Phase 2 must not proceed.
//!
//! `decide()` returns immediately — no blocking, no I/O, no queue.
//!
//! ## Phase 2 — `decide_with_approval()` evaluates the grant
//!
//! The gateway feeds a signed [`ApprovalGrant`] from the human approver.
//! `decide_with_approval()`:
//! 1. Hard-denies Forbidden-domain tools unconditionally (no grant can override this).
//! 2. Validates the grant against the pending binding (binding_id, request_hash, TTL, signature).
//! 3. On success, runs the full `decide()` pipeline with the escalation trigger removed.
//! 4. The resulting ALLOW receipt carries `parent_receipt_hash` pointing to the Phase 1 receipt,
//!    making the full causal chain reconstructible from the ledger.
//!
//! ## Cross-request replay prevention
//!
//! `request_hash` includes the mandate hash, tool name, params hash, and Phase 1 timestamp.
//! An approver's grant for action A cannot be replayed to authorize action B — the hashes differ.
//!
//! ## Replay-via-time prevention
//!
//! Grants are TTL'd. A valid grant issued during a legitimate approval cannot be reused
//! after its `expires_at`. The pending binding is also TTL'd.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cbor::{encode_canonical, GrantPayload};
use crate::error::A2gError;

/// Default pending-approval TTL: 5 minutes.
pub const PENDING_APPROVAL_TTL_MINUTES: i64 = 5;

/// Binding produced by Phase 1 when `decide()` returns `Decision::PendingApproval`.
///
/// Callers (the gateway or test harness) must persist this so they can feed it
/// together with an [`ApprovalGrant`] into `decide_with_approval()` (Phase 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApprovalBinding {
    /// UUID v4 uniquely identifying this pending request.
    pub binding_id: String,
    /// SHA-256 binding over (mandate_hash, tool, params_hash, timestamp).
    /// Phase 2 grant must carry the same hash; cross-request replay is rejected.
    pub request_hash: String,
    /// DID of the required approver, copied from `mandate.escalation.escalate_to`.
    pub escalate_to: String,
    /// UTC deadline; Phase 2 must complete before this instant.
    pub ttl_expires_at: DateTime<Utc>,
}

/// Signed approval token produced by the human approver. Consumed by Phase 2.
///
/// The approver signs over the SHA-256 of
/// `"APPROVAL:<binding_id>:<request_hash>:<expires_at>"`.
/// Domain separation (`"APPROVAL:"` prefix) prevents this signature from being
/// valid in any other A2G context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalGrant {
    /// Must match `PendingApprovalBinding.binding_id`.
    pub binding_id: String,
    /// Must match `PendingApprovalBinding.request_hash`.
    /// Mismatch → DENY; prevents approving action A from authorising action B.
    pub request_hash: String,
    /// DID of the approver who produced this grant.
    pub approver_did: String,
    /// Hex-encoded ed25519 public key of the approver.
    pub approver_pubkey: String,
    /// Hex-encoded ed25519 signature over the payload hash.
    pub signature: String,
    /// RFC3339 expiry timestamp. Grant is rejected at or after this time.
    pub expires_at: String,
    /// Receipt hash of the Phase 1 `PendingApproval` receipt.
    /// Phase 2 copies this into `Verdict.parent_receipt_hash` for ledger chain linking.
    pub parent_receipt_hash: String,
}

/// A `PendingApprovalBinding` signed by the Enforcing Gateway's binding key
/// (SPEC §9.7 SignBinding, §9.8 key ownership; ADR-0015).
///
/// Only the gateway holds the binding-signing key. The rich domain receives
/// this blob opaquely from the gateway's `SignBinding` operation and presents
/// it unmodified at Phase 2, where it is verified against the gateway's
/// binding *verifying* key. The rich domain cannot manufacture a valid
/// `SignedBinding` — it holds no signing key for bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBinding {
    /// The binding fields, flattened into the same JSON object.
    #[serde(flatten)]
    pub binding: PendingApprovalBinding,
    /// Hex ed25519 signature by the gateway's binding-signing key over the
    /// canonical CBOR `BindingPayload` (ADR-0011).
    pub a2g_mac: String,
}

impl SignedBinding {
    /// Canonical CBOR bytes covered by the binding signature (ADR-0011):
    /// `["BINDING", binding_id, request_hash(bstr 32B), escalate_to, ttl_unix_secs]`.
    pub fn payload_bytes(binding: &PendingApprovalBinding) -> Result<Vec<u8>, A2gError> {
        let hash_bytes =
            hex::decode(&binding.request_hash).map_err(|e| A2gError::HexDecode(e.to_string()))?;
        encode_canonical(&crate::cbor::BindingPayload {
            tag: "BINDING".to_string(),
            binding_id: binding.binding_id.clone(),
            request_hash: hash_bytes.into(),
            escalate_to: binding.escalate_to.clone(),
            ttl_unix_secs: binding.ttl_expires_at.timestamp(),
        })
    }

    /// Sign a binding. Called by the Enforcing Gateway only — the binding
    /// signing key MUST NOT exist in the rich domain (SPEC §9.8, §11.1).
    pub fn sign(binding: &PendingApprovalBinding, key: &SigningKey) -> Result<Self, A2gError> {
        let payload = Self::payload_bytes(binding)?;
        let sig: Signature = key.sign(&payload);
        Ok(SignedBinding {
            binding: binding.clone(),
            a2g_mac: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify the gateway signature and return the inner binding.
    ///
    /// Any field modification (including `ttl_expires_at`) invalidates the
    /// signature and returns `A2gError::SignatureInvalid`.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<PendingApprovalBinding, A2gError> {
        let payload = Self::payload_bytes(&self.binding)?;
        let sig_bytes =
            hex::decode(&self.a2g_mac).map_err(|e| A2gError::HexDecode(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| A2gError::SignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&payload, &sig)
            .map_err(|_| A2gError::SignatureInvalid)?;
        Ok(self.binding.clone())
    }

    /// Parse a signed-binding JSON blob and verify it in one step.
    pub fn verify_json(
        json: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<PendingApprovalBinding, A2gError> {
        let signed: SignedBinding = serde_json::from_str(json)
            .map_err(|e| A2gError::Json(format!("signed binding JSON: {e}")))?;
        signed.verify(verifying_key)
    }
}

/// Compute the `request_hash` that binds an approval to a specific action.
///
/// Payload: `"REQUEST:<mandate_hash>:<tool>:<params_hash>:<timestamp>"`.
/// The `"REQUEST:"` prefix is a domain separator.
pub fn compute_request_hash(
    mandate_hash: &str,
    tool: &str,
    params_hash: &str,
    timestamp: &str,
) -> String {
    let payload = format!(
        "REQUEST:{}:{}:{}:{}",
        mandate_hash, tool, params_hash, timestamp
    );
    hex::encode(Sha256::digest(payload.as_bytes()))
}

impl ApprovalGrant {
    /// Create and sign a new grant. Used by the gateway or in tests.
    ///
    /// Signs over the canonical CBOR encoding of
    /// `["APPROVAL", binding_id, request_hash(bstr), expires_at]`.
    pub fn new_signed(
        binding_id: &str,
        request_hash: &str,
        approver_did: &str,
        signing_key: &SigningKey,
        ttl_seconds: u64,
        now: DateTime<Utc>,
        parent_receipt_hash: &str,
    ) -> Result<Self, A2gError> {
        let ttl_secs = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
        let expires_at = now
            .checked_add_signed(Duration::seconds(ttl_secs))
            .unwrap_or(now)
            .to_rfc3339();
        let approver_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let payload_bytes = Self::payload_bytes(binding_id, request_hash, &expires_at)?;
        let sig: Signature = signing_key.sign(&payload_bytes);
        Ok(ApprovalGrant {
            binding_id: binding_id.to_string(),
            request_hash: request_hash.to_string(),
            approver_did: approver_did.to_string(),
            approver_pubkey,
            signature: hex::encode(sig.to_bytes()),
            expires_at,
            parent_receipt_hash: parent_receipt_hash.to_string(),
        })
    }

    /// Validate this grant against its corresponding [`PendingApprovalBinding`].
    ///
    /// Checks in order (fail-fast):
    /// 1. `binding_id` must match the pending binding.
    /// 2. `request_hash` must match the pending binding (cross-request replay prevention).
    /// 3. Grant `expires_at` must be in the future (replay-via-time prevention).
    /// 4. ed25519 signature must verify against `approver_pubkey`.
    pub fn verify_against_binding(
        &self,
        pending: &PendingApprovalBinding,
        now: DateTime<Utc>,
    ) -> Result<(), A2gError> {
        if self.binding_id != pending.binding_id {
            return Err(A2gError::BindingMismatch {
                field: "binding_id",
            });
        }
        if self.request_hash != pending.request_hash {
            return Err(A2gError::BindingMismatch {
                field: "request_hash",
            });
        }
        let expires = self
            .expires_at
            .parse::<DateTime<Utc>>()
            .map_err(|_| A2gError::GrantExpired)?;
        if now >= expires {
            return Err(A2gError::GrantExpired);
        }
        let pubkey_bytes =
            hex::decode(&self.approver_pubkey).map_err(|e| A2gError::HexDecode(e.to_string()))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| A2gError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| A2gError::InvalidKey)?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| A2gError::HexDecode(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| A2gError::SignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_arr);
        let payload_bytes =
            Self::payload_bytes(&self.binding_id, &self.request_hash, &self.expires_at)?;
        verifying_key
            .verify(&payload_bytes, &sig)
            .map_err(|_| A2gError::SignatureInvalid)?;
        Ok(())
    }

    fn payload_bytes(
        binding_id: &str,
        request_hash: &str,
        expires_at: &str,
    ) -> Result<Vec<u8>, A2gError> {
        let hash_bytes =
            hex::decode(request_hash).map_err(|e| A2gError::HexDecode(e.to_string()))?;
        let payload = GrantPayload {
            tag: "APPROVAL".to_string(),
            binding_id: binding_id.to_string(),
            request_hash: hash_bytes.into(),
            expires_at: expires_at.to_string(),
        };
        encode_canonical(&payload)
    }
}
