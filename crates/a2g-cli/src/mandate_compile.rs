//! TOML → signed canonical CBOR mandate compiler (CLI layer, ADR-0013).
//!
//! This module is the only place in the workspace where TOML is parsed for
//! mandate authoring. `a2g-core` never sees TOML; it receives CBOR bytes only.
//!
//! # Flow
//!
//! ```text
//! TOML file  ─parse_toml_mandate()──▶  Mandate struct
//!                                           │
//!                              compile_mandate()
//!                                           │
//!                              MandateTbs (fill fields)
//!                                           │
//!                              encode_canonical(MandateTbs) ──▶ tbs_bytes
//!                                           │
//!                              ed25519.sign(tbs_bytes) ──▶ signature
//!                                           │
//!                              CborMandate { tag, tbs, sig, pubkey }
//!                                           │
//!                              encode_canonical(CborMandate) ──▶ Vec<u8>
//! ```

use a2g_core::cbor::{encode_canonical, CborMandate, MandateTbs};
use a2g_core::mandate::{self, Mandate};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use minicbor::bytes::ByteVec;
use sha2::{Digest, Sha256};

/// Parse a TOML mandate document into a `Mandate` struct.
///
/// This is the authoring entry-point used by `cmd_sign` and `cmd_propose`.
pub fn parse_toml_mandate(toml_str: &str) -> Result<Mandate, Box<dyn std::error::Error>> {
    let m: Mandate = toml::from_str(toml_str)?;
    Ok(m)
}

/// Compile a `Mandate` to a signed CBOR envelope.
///
/// # Parameters
/// - `m`: The mandate to compile (parsed from TOML by the caller).
/// - `key_hex`: hex-encoded 32-byte ed25519 signing key (the issuer's private key).
/// - `ttl_hours`: validity period; overwrites any `expires_at` in the TOML.
/// - `proposal_hash`: optional proposal hash to embed in the envelope.
///
/// # Returns
/// Canonical CBOR bytes of a `CborMandate` envelope, ready to write to disk.
pub fn compile_mandate(
    m: &Mandate,
    key_hex: &str,
    ttl_hours: u64,
    proposal_hash: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Decode signing key
    let key_bytes = hex::decode(key_hex.trim())?;
    if key_bytes.len() != 32 {
        return Err(format!("signing key must be 32 bytes, got {}", key_bytes.len()).into());
    }
    let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| "key conversion failed")?;
    let signing_key = SigningKey::from_bytes(&key_arr);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let issuer_did = format!("did:a2g:{}", bs58::encode(&pubkey_bytes).into_string());

    // Compute timestamps
    let now = Utc::now();
    let issued_at = now.to_rfc3339();
    let ttl_i64 = i64::try_from(ttl_hours).unwrap_or(i64::MAX);
    let expires_at = now
        .checked_add_signed(chrono::Duration::hours(ttl_i64))
        .unwrap_or(now)
        .to_rfc3339();

    // Compute capabilities_hash (§4.5)
    let cap_hash_hex = mandate::capabilities_hash(&m.capabilities.tools);
    let cap_hash_bytes =
        hex::decode(&cap_hash_hex).map_err(|e| format!("capabilities_hash decode: {}", e))?;

    // Build MandateTbs
    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did: m.mandate.agent_did.clone(),
        issuer_did: issuer_did.clone(),
        agent_name: m.mandate.agent_name.clone(),
        issued_at,
        expires_at,
        proposal_hash: proposal_hash.to_string(),
        workspace_root: m.mandate.workspace_root.clone(),
        capabilities_hash: ByteVec::from(cap_hash_bytes),
        tools: m.capabilities.tools.clone(),
        fs_read: m.boundaries.fs_read.clone(),
        fs_write: m.boundaries.fs_write.clone(),
        fs_deny: m.boundaries.fs_deny.clone(),
        net_allow: m.boundaries.net_allow.clone(),
        net_deny: m.boundaries.net_deny.clone(),
        cmd_allow: m.boundaries.cmd_allow.clone(),
        cmd_deny: m.boundaries.cmd_deny.clone(),
        max_calls_per_minute: m.limits.max_calls_per_minute,
        max_file_size_bytes: m.limits.max_file_size_bytes,
        max_output_tokens: m.limits.max_output_tokens,
        max_session_duration_sec: m.limits.max_session_duration_sec,
        deny_patterns: m.output_governance.deny_patterns.clone(),
        redact_patterns: m.output_governance.redact_patterns.clone(),
        max_output_length: m.output_governance.max_output_length,
        region: m.jurisdiction.region.clone(),
        regulatory_framework: m.jurisdiction.regulatory_framework.clone(),
        environment: m.jurisdiction.environment.clone(),
        classification: m.jurisdiction.classification.clone(),
        operating_hours: m.jurisdiction.operating_hours.clone(),
        escalate_tools: m.escalation.escalate_tools.clone(),
        escalate_paths: m.escalation.escalate_paths.clone(),
        escalate_hosts: m.escalation.escalate_hosts.clone(),
        escalate_to: m.escalation.escalate_to.clone(),
    };

    // Encode TBS to canonical CBOR
    let tbs_bytes = encode_canonical(&tbs).map_err(|e| e.to_string())?;

    // Sign TBS bytes
    let signature = signing_key.sign(&tbs_bytes);
    let sig_bytes = signature.to_bytes().to_vec();

    // Build envelope
    let envelope = CborMandate {
        tag: "MANDATE-V1".to_string(),
        tbs: ByteVec::from(tbs_bytes),
        signature: ByteVec::from(sig_bytes),
        issuer_pubkey: ByteVec::from(pubkey_bytes.to_vec()),
    };

    // Encode envelope
    let cbor_bytes = encode_canonical(&envelope).map_err(|e| e.to_string())?;
    Ok(cbor_bytes)
}

/// Compute the SHA-256 hash of a TOML mandate body string (for proposal anchoring).
///
/// This hash is stored in proposals to detect mandate tampering after approval.
/// It is computed over the raw TOML bytes, not over the compiled CBOR.
pub fn mandate_body_hash(toml_str: &str) -> String {
    hex::encode(Sha256::digest(toml_str.as_bytes()))
}
