//! Unified error type for the a2g-core public API (ADR-0012).
//!
//! `std::error::Error` is implemented only behind the `std` feature so the
//! decision path stays no_std-capable.

/// Unified error type for the a2g-core public API.
///
/// Replaces `Box<dyn std::error::Error>`, `&'static str`, and the prior
/// `ApprovalGrantError` / `AttestationError` ad-hoc enums.
#[derive(Debug)]
#[non_exhaustive]
pub enum A2gError {
    // ── Parse / decode ────────────────────────────────────────────────────────
    /// TOML mandate text could not be parsed.
    MandateParse(String),
    /// JSON serialization or deserialization failed.
    Json(String),
    /// Hex-encoded bytes were malformed.
    HexDecode(String),

    // ── Cryptographic ─────────────────────────────────────────────────────────
    /// ed25519 signature did not verify.
    SignatureInvalid,
    /// A public or signing key could not be decoded.
    InvalidKey,

    // ── CBOR ──────────────────────────────────────────────────────────────────
    /// CBOR encoding failed.
    CborEncode,
    /// CBOR decoding failed.
    CborDecode,

    // ── Mandate / grant validity ──────────────────────────────────────────────
    /// Mandate TTL has elapsed.
    MandateExpired,
    /// Mandate is structurally invalid (missing field, bad value, etc.).
    MandateInvalid(String),
    /// Approval grant TTL has elapsed.
    GrantExpired,
    /// A binding field did not match the pending binding.
    BindingMismatch { field: &'static str },

    // ── Authority chain ───────────────────────────────────────────────────────
    /// Authority delegation chain validation failed.
    AuthorityChain(String),

    // ── Vehicle / attestation ─────────────────────────────────────────────────
    /// Speed value was out of range or non-finite.
    InvalidSpeed(String),
    /// Vehicle state attestation: signature did not verify.
    AttestationBadSignature,
    /// Vehicle state attestation: attester key is invalid.
    AttestationInvalidKey,
    /// Vehicle state attestation: nonce/challenge did not match.
    AttestationStaleNonce,
    /// Vehicle state attestation: timestamp is outside the freshness window.
    AttestationStale,

    // ── I/O helpers (std-only callers) ────────────────────────────────────────
    /// Filesystem path resolution failed.
    PathError(String),

    // ── Ledger / rate-limit ────────────────────────────────────────────────────
    /// An `EnforceLedger` implementation returned an error.
    LedgerError(String),

    // ── Trust anchor ──────────────────────────────────────────────────────────
    /// Mandate issuer is not in the caller-supplied trust anchor.
    /// Returned by `check_issuer_trust` when `TrustAnchor::Roots` or
    /// `TrustAnchor::Chain` is used and the issuer does not match.
    IssuerUntrusted,

    // ── Catch-all ─────────────────────────────────────────────────────────────
    /// Internal invariant violated.
    Internal(String),
}

impl core::fmt::Display for A2gError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            A2gError::MandateParse(s) => write!(f, "mandate parse error: {s}"),
            A2gError::Json(s) => write!(f, "JSON error: {s}"),
            A2gError::HexDecode(s) => write!(f, "hex decode error: {s}"),
            A2gError::SignatureInvalid => write!(f, "signature verification failed"),
            A2gError::InvalidKey => write!(f, "invalid cryptographic key"),
            A2gError::CborEncode => write!(f, "CBOR encoding failed"),
            A2gError::CborDecode => write!(f, "CBOR decoding failed"),
            A2gError::MandateExpired => write!(f, "mandate has expired"),
            A2gError::MandateInvalid(s) => write!(f, "mandate invalid: {s}"),
            A2gError::GrantExpired => write!(f, "approval grant has expired"),
            A2gError::BindingMismatch { field } => write!(f, "binding mismatch: {field}"),
            A2gError::AuthorityChain(s) => write!(f, "authority chain error: {s}"),
            A2gError::InvalidSpeed(s) => write!(f, "invalid speed: {s}"),
            A2gError::AttestationBadSignature => {
                write!(f, "attestation signature did not verify")
            }
            A2gError::AttestationInvalidKey => write!(f, "attestation key is invalid"),
            A2gError::AttestationStaleNonce => write!(f, "attestation nonce mismatch"),
            A2gError::AttestationStale => write!(f, "attested state is too old"),
            A2gError::IssuerUntrusted => write!(f, "issuer not in configured trust roots"),
            A2gError::PathError(s) => write!(f, "path error: {s}"),
            A2gError::LedgerError(s) => write!(f, "ledger error: {s}"),
            A2gError::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for A2gError {}
