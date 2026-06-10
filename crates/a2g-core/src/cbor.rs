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

/// Encode `val` into canonical CBOR bytes.
///
/// minicbor array encoding is inherently deterministic: element order equals
/// declaration order. No key sorting is needed.
pub fn encode_canonical<T: Encode<()>>(val: &T) -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    minicbor::encode(val, &mut buf).map_err(|_| "cbor encode failed")?;
    Ok(buf)
}

/// Decode `bytes` as a `T` from CBOR.
pub fn decode_canonical<'a, T: Decode<'a, ()>>(bytes: &'a [u8]) -> Result<T, &'static str> {
    minicbor::decode(bytes).map_err(|_| "cbor decode failed")
}
