//! Canonical CBOR wire-format types for signed payloads (ADR-0011).
//!
//! `#[cbor(array)]` with `#[n(idx)]` positional fields produces deterministic
//! output: element order equals declaration order, no key-sorting required.
//!
//! Binary fields (SHA-256 digests, nonces) are encoded as CBOR `bstr` via
//! `minicbor::bytes::ByteVec`, not as integer arrays.
//!
//! no_std: minicbor supports `default-features = false, features = ["derive",
//! "alloc"]`. See `docs/no_std-blockers.md` for current blockers keeping
//! a2g-core on std.

use crate::error::A2gError;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

/// CBOR array for `PendingApprovalBinding` MAC (gateway and FFI paths).
///
/// `["BINDING", binding_id, request_hash(bstr 32B), escalate_to, ttl_unix_secs]`
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct BindingPayload {
    #[n(0)]
    pub tag: String,
    #[n(1)]
    pub binding_id: String,
    #[n(2)]
    pub request_hash: ByteVec,
    #[n(3)]
    pub escalate_to: String,
    #[n(4)]
    pub ttl_unix_secs: i64,
}

/// CBOR array for `ApprovalGrant` signing.
///
/// `["APPROVAL", binding_id, request_hash(bstr 32B), expires_at(tstr RFC3339)]`
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct GrantPayload {
    #[n(0)]
    pub tag: String,
    #[n(1)]
    pub binding_id: String,
    #[n(2)]
    pub request_hash: ByteVec,
    #[n(3)]
    pub expires_at: String,
}

/// CBOR mandate to-be-signed content (SPEC §4.5, ADR-0013).
///
/// Positional array encoding is deterministic: element order equals declaration order.
/// Signature: `ed25519.sign(encode_canonical(&MandateTbs))`.
/// `capabilities_hash` = SHA-256 of tools sorted lexicographically, joined with `\n` (§4.5 rule preserved).
#[derive(Debug, Encode, Decode, Clone)]
#[cbor(array)]
pub struct MandateTbs {
    #[n(0)]  pub tag: String,
    #[n(1)]  pub agent_did: String,
    #[n(2)]  pub issuer_did: String,
    #[n(3)]  pub agent_name: String,
    #[n(4)]  pub issued_at: String,
    #[n(5)]  pub expires_at: String,
    #[n(6)]  pub proposal_hash: String,
    #[n(7)]  pub workspace_root: String,
    #[n(8)]  pub capabilities_hash: ByteVec,
    #[n(9)]  pub tools: Vec<String>,
    #[n(10)] pub fs_read: Vec<String>,
    #[n(11)] pub fs_write: Vec<String>,
    #[n(12)] pub fs_deny: Vec<String>,
    #[n(13)] pub net_allow: Vec<String>,
    #[n(14)] pub net_deny: Vec<String>,
    #[n(15)] pub cmd_allow: Vec<String>,
    #[n(16)] pub cmd_deny: Vec<String>,
    #[n(17)] pub max_calls_per_minute: u64,
    #[n(18)] pub max_file_size_bytes: u64,
    #[n(19)] pub max_output_tokens: u64,
    #[n(20)] pub max_session_duration_sec: u64,
    #[n(21)] pub deny_patterns: Vec<String>,
    #[n(22)] pub redact_patterns: Vec<String>,
    #[n(23)] pub max_output_length: u64,
    #[n(24)] pub region: String,
    #[n(25)] pub regulatory_framework: String,
    #[n(26)] pub environment: String,
    #[n(27)] pub classification: String,
    #[n(28)] pub operating_hours: String,
    #[n(29)] pub escalate_tools: Vec<String>,
    #[n(30)] pub escalate_paths: Vec<String>,
    #[n(31)] pub escalate_hosts: Vec<String>,
    #[n(32)] pub escalate_to: String,
}

/// CBOR mandate distribution envelope (ADR-0013).
///
/// `["MANDATE-V1", tbs_cbor(bstr), signature(bstr 64B), issuer_pubkey(bstr 32B)]`
///
/// Compile: encode `MandateTbs` → `tbs_cbor`; sign `tbs_cbor` → `signature`; encode envelope.
/// Verify: decode envelope; verify ed25519 sig over `tbs`; decode `MandateTbs`; check `capabilities_hash` and `issuer_did`.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CborMandate {
    #[n(0)] pub tag: String,
    #[n(1)] pub tbs: ByteVec,
    #[n(2)] pub signature: ByteVec,
    #[n(3)] pub issuer_pubkey: ByteVec,
}

/// Encode `val` into canonical CBOR bytes.
///
/// minicbor array encoding is inherently deterministic: element order equals
/// declaration order. No key sorting is needed.
pub fn encode_canonical<T: Encode<()>>(val: &T) -> Result<Vec<u8>, A2gError> {
    let mut buf = Vec::new();
    minicbor::encode(val, &mut buf).map_err(|_| A2gError::CborEncode)?;
    Ok(buf)
}

/// Decode `bytes` as a `T` from CBOR.
pub fn decode_canonical<'a, T: Decode<'a, ()>>(bytes: &'a [u8]) -> Result<T, A2gError> {
    minicbor::decode(bytes).map_err(|_| A2gError::CborDecode)
}
