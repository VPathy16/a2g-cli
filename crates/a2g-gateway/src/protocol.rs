//! Wire protocol for the A2G Enforcing Gateway (ADR-0010).
//!
//! All messages are newline-delimited JSON over a Unix domain socket.
//! One request per connection; server responds then closes the connection.

use a2g_core::cbor::encode_canonical;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical CBOR array for `GatewayReceipt` signing (ADR-0011).
///
/// `["RECEIPT", verdict_id, decision, tool, request_hash(bstr 32B),
///  binding_id, issued_at_ms, nonce(bstr 16B)]`
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct ReceiptPayload {
    #[n(0)]
    pub tag: String,
    #[n(1)]
    pub verdict_id: String,
    #[n(2)]
    pub decision: String,
    #[n(3)]
    pub tool: String,
    #[n(4)]
    pub request_hash: ByteVec,
    #[n(5)]
    pub binding_id: String,
    #[n(6)]
    pub issued_at_ms: i64,
    #[n(7)]
    pub nonce: ByteVec,
}

/// A receipt produced by the rich domain for an ALLOW verdict.
///
/// The gateway verifies this before any bus write. The canonical signed payload
/// is canonical CBOR (ADR-0011): a `ReceiptPayload` array encoding
/// `["RECEIPT", verdict_id, decision, tool, request_hash(bstr), binding_id,
///  issued_at_ms, nonce(bstr)]`.
///
/// `request_hash = SHA-256(tool || params_json || issued_at_ms.to_string())`
/// so the full params are covered by the hash without being in the signed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayReceipt {
    /// UUID from the a2g-core Verdict.
    pub verdict_id: String,
    /// Must be "ALLOW"; any other value is rejected at step 3.
    pub decision: String,
    /// Tool name exactly as submitted to `decide()`.
    pub tool: String,
    /// Full params JSON exactly as submitted to `decide()`.
    pub params_json: String,
    /// `Verdict.policy_rule` (informational; not in signed payload).
    pub policy_rule: String,
    /// "attested" | "operator_trusted" | "none"
    pub state_trust: String,
    /// Empty for single-phase actions. Set to `PendingApprovalBinding.binding_id` for Phase 2.
    pub binding_id: String,
    /// SHA-256(tool || params_json || issued_at_ms.to_string())
    pub request_hash: String,
    /// Unix milliseconds at receipt construction.  Freshness window: ±2 000 ms.
    pub issued_at_ms: i64,
    /// 16 random bytes, hex-encoded.  Anti-replay nonce.
    pub nonce_hex: String,
    /// ed25519 over the canonical payload, hex-encoded.
    pub signature_hex: String,
    /// Optional: `AttestedVehicleState` JSON for gateway-side attestation verification.
    /// Required for Sensitive-domain tools; gateway rejects "attested" state_trust
    /// if it cannot independently verify this blob.
    pub attested_state_json: Option<String>,
}

impl GatewayReceipt {
    /// Canonical CBOR bytes that are signed and verified (ADR-0011).
    ///
    /// Returns `Err` if `request_hash` or `nonce_hex` are not valid hex strings.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, a2g_core::A2gError> {
        let request_hash = hex::decode(&self.request_hash)
            .map_err(|e| a2g_core::A2gError::HexDecode(e.to_string()))?;
        let nonce = hex::decode(&self.nonce_hex)
            .map_err(|e| a2g_core::A2gError::HexDecode(e.to_string()))?;
        let payload = ReceiptPayload {
            tag: "RECEIPT".to_string(),
            verdict_id: self.verdict_id.clone(),
            decision: self.decision.clone(),
            tool: self.tool.clone(),
            request_hash: request_hash.into(),
            binding_id: self.binding_id.clone(),
            issued_at_ms: self.issued_at_ms,
            nonce: nonce.into(),
        };
        encode_canonical(&payload)
    }

    /// Compute the expected `request_hash` from the receipt fields.
    pub fn expected_request_hash(&self) -> String {
        Self::compute_request_hash(&self.tool, &self.params_json, self.issued_at_ms)
    }

    /// `SHA-256(tool || params_json || issued_at_ms.to_string())`
    pub fn compute_request_hash(tool: &str, params_json: &str, issued_at_ms: i64) -> String {
        let payload = format!("{}{}{}", tool, params_json, issued_at_ms);
        hex::encode(Sha256::digest(payload.as_bytes()))
    }
}

/// Messages the rich domain sends to the gateway over the socket.
#[derive(Debug, Serialize, Deserialize)]
pub enum GatewayRequest {
    /// Phase 1: gateway signs a `PendingApprovalBinding` and queues it.
    /// Rich domain sends the unsigned binding JSON from `Verdict.pending_approval`.
    /// Gateway returns MAC-protected `SignedBinding` JSON.
    SignBinding { binding_json: String },

    /// Operator submits a signed `ApprovalGrant` to approve a queued binding.
    /// Gateway verifies the grant signature against the known operator key and
    /// marks the binding as approved.
    SubmitGrant { grant_json: String },

    /// Rich domain presents a signed `GatewayReceipt` for enforcement on the bus.
    /// Gateway applies the 7-step verification (forbidden first) before any write.
    Enforce { receipt: Box<GatewayReceipt> },

    /// Demo-only: retrieve verifying public keys for client bootstrapping.
    /// Returns public keys only — no private key ever leaves the gateway.
    GetPublicKeys,
}

/// Messages the gateway sends back to the rich domain.
#[derive(Debug, Serialize, Deserialize)]
pub enum GatewayResponse {
    /// Binding signed and queued.  `signed_json` is the MAC-protected blob
    /// the rich domain must pass unmodified to Phase 2.
    SignedBinding {
        signed_json: String,
    },

    /// Grant accepted; binding marked as approved in the pending queue.
    GrantAccepted {
        binding_id: String,
    },

    /// Receipt verified and action enforced on the bus.
    /// `frame_hex` is the 8-byte CAN frame that was written (real or simulated).
    /// `real_write` is `true` when a real SocketCAN write was performed; `false`
    /// when the CI-only simulated bus fallback was used (vcan module absent).
    /// Defaults to `false` for backward-compatible deserialization.
    Enforced {
        verdict_id: String,
        frame_hex: String,
        #[serde(default)]
        real_write: bool,
    },

    /// Receipt or grant rejected.  No bus write occurred.
    Refused {
        reason: String,
    },

    /// Demo-only public key bundle.  Contains verifying keys only.
    /// Private keys for demo use are in the demo key file.
    PublicKeys {
        receipt_verifying_key_hex: String,
        attester_verifying_key_hex: String,
        operator_verifying_key_hex: String,
        /// Gateway's binding verifying key — the rich domain verifies
        /// gateway-signed bindings at Phase 2 with this (ADR-0015).
        #[serde(default)]
        binding_verifying_key_hex: String,
    },

    Error {
        message: String,
    },
}
