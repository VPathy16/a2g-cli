//! Mandate — Canonical policy documents with CBOR encoding and ed25519 signing.
//!
//! **Authoring format:** TOML (human-readable, CLI/std side only).
//! **Distribution/verification format:** canonical CBOR (RFC 8949, ADR-0013).
//!
//! `a2g-core` only ever sees CBOR bytes. The `toml` crate does not appear here.
//! TOML→CBOR compile+sign lives in the CLI layer (`a2g-cli/src/mandate_compile.rs`).
//!
//! Signing (Option b, ADR-0013): the ed25519 signature is over
//! `encode_canonical(&MandateTbs)`. The `capabilities_hash` field inside `MandateTbs`
//! preserves the §4.5 canonicalization rule (SHA-256 of sorted tools joined with `\n`).

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cbor::{decode_canonical, CborMandate, MandateTbs};
use crate::error::A2gError;

/// Information extracted from a verified mandate
pub struct MandateInfo {
    pub agent_did: String,
    pub agent_name: String,
    pub issuer: String,
    pub expires_at: String,
    pub ttl_remaining_sec: i64,
    pub tools: Vec<String>,
}

/// Runtime mandate structure (populated from CBOR, used by enforce.rs).
#[derive(Debug, Deserialize, Serialize)]
pub struct Mandate {
    pub mandate: MandateHeader,
    pub capabilities: Capabilities,
    pub boundaries: Boundaries,
    pub limits: Limits,
    #[serde(default)]
    pub output_governance: OutputGovernance,
    #[serde(default)]
    pub jurisdiction: MandateJurisdiction,
    #[serde(default)]
    pub escalation: EscalationRules,
    #[serde(default)]
    pub signature: Option<MandateSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MandateHeader {
    pub version: String,
    pub agent_did: String,
    pub agent_name: String,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub proposal_hash: String,
    #[serde(default)]
    pub workspace_root: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Capabilities {
    pub tools: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Boundaries {
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_deny: Vec<String>,
    #[serde(default)]
    pub net_allow: Vec<String>,
    #[serde(default)]
    pub net_deny: Vec<String>,
    #[serde(default)]
    pub cmd_allow: Vec<String>,
    #[serde(default)]
    pub cmd_deny: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Limits {
    #[serde(default = "default_rate")]
    pub max_calls_per_minute: u64,
    #[serde(default = "default_file_size")]
    pub max_file_size_bytes: u64,
    #[serde(default = "default_tokens")]
    pub max_output_tokens: u64,
    #[serde(default = "default_session")]
    pub max_session_duration_sec: u64,
}

fn default_rate() -> u64 {
    60
}
fn default_file_size() -> u64 {
    10_485_760
}
fn default_tokens() -> u64 {
    4096
}
fn default_session() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct OutputGovernance {
    #[serde(default)]
    pub deny_patterns: Vec<String>,
    #[serde(default)]
    pub redact_patterns: Vec<String>,
    #[serde(default = "default_output_len")]
    pub max_output_length: u64,
}

fn default_output_len() -> u64 {
    50_000
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct MandateJurisdiction {
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub regulatory_framework: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub operating_hours: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct EscalationRules {
    #[serde(default)]
    pub escalate_tools: Vec<String>,
    #[serde(default)]
    pub escalate_paths: Vec<String>,
    #[serde(default)]
    pub escalate_hosts: Vec<String>,
    #[serde(default)]
    pub escalate_to: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MandateSignature {
    pub algorithm: String,
    pub issuer_pubkey: String,
    pub signature: String,
    pub signed_at: String,
}

/// Sanitize an agent name: strip control characters, cap length.
pub fn sanitize_name(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Generate a TOML mandate template for a new agent.
/// The template is an authoring artifact — it must be compiled to CBOR before use.
pub fn generate_template(name: &str, did: &str) -> String {
    let name = sanitize_name(name);
    format!(
        r#"[mandate]
version = "0.1.0"
agent_did = "{did}"
agent_name = "{name}"
issued_at = ""
expires_at = ""
issuer = ""
workspace_root = ""

[capabilities]
# Explicit allow-list. Anything not listed here is DENIED.
tools = ["read_file", "write_file"]

[boundaries]
# Filesystem boundaries (glob patterns)
fs_read = ["workspace/**"]
fs_write = ["workspace/output/**"]
fs_deny = ["/etc/**", "~/.ssh/**", "**/*.env", "**/*secret*"]

# Network boundaries
net_allow = []
net_deny = ["*"]

# Command boundaries
cmd_allow = []
cmd_deny = ["rm", "sudo", "chmod", "curl * | *"]

[limits]
max_calls_per_minute = 60
max_file_size_bytes = 10485760
max_output_tokens = 4096
max_session_duration_sec = 3600

[output_governance]
deny_patterns = ["-----BEGIN.*PRIVATE KEY-----", "sk-[a-zA-Z0-9]{{48}}", "AKIA[0-9A-Z]{{16}}"]
redact_patterns = ["\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b"]
max_output_length = 50000

[jurisdiction]
region = ""
regulatory_framework = ""
environment = ""
classification = ""
operating_hours = ""

[escalation]
# Tools that require human approval before execution
escalate_tools = []
# Path patterns that trigger escalation
escalate_paths = []
# Network patterns that trigger escalation
escalate_hosts = []
# DID of the authority to escalate to
escalate_to = ""
"#
    )
}

/// Compute the `capabilities_hash` component (SPEC §4.5).
///
/// **Algorithm (normative — preserved in ADR-0013):**
/// 1. Sort `tools` lexicographically (ascending UTF-8 byte order).
/// 2. Join with U+000A LINE FEED. Empty list → empty string.
/// 3. SHA-256 of the UTF-8 bytes.
/// 4. Hex-encode lowercase.
pub fn capabilities_hash(tools: &[String]) -> String {
    let mut sorted = tools.to_vec();
    sorted.sort();
    let joined = sorted.join("\n");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

// ── Internal CBOR decode helpers ──────────────────────────────────────────────

/// Convert a decoded `MandateTbs` to the runtime `Mandate` struct.
fn tbs_to_mandate(tbs: &MandateTbs) -> Mandate {
    Mandate {
        mandate: MandateHeader {
            version: "0.1.0".to_string(),
            agent_did: tbs.agent_did.clone(),
            agent_name: tbs.agent_name.clone(),
            issued_at: tbs.issued_at.clone(),
            expires_at: tbs.expires_at.clone(),
            issuer: tbs.issuer_did.clone(),
            proposal_hash: tbs.proposal_hash.clone(),
            workspace_root: tbs.workspace_root.clone(),
        },
        capabilities: Capabilities {
            tools: tbs.tools.clone(),
        },
        boundaries: Boundaries {
            fs_read: tbs.fs_read.clone(),
            fs_write: tbs.fs_write.clone(),
            fs_deny: tbs.fs_deny.clone(),
            net_allow: tbs.net_allow.clone(),
            net_deny: tbs.net_deny.clone(),
            cmd_allow: tbs.cmd_allow.clone(),
            cmd_deny: tbs.cmd_deny.clone(),
        },
        limits: Limits {
            max_calls_per_minute: tbs.max_calls_per_minute,
            max_file_size_bytes: tbs.max_file_size_bytes,
            max_output_tokens: tbs.max_output_tokens,
            max_session_duration_sec: tbs.max_session_duration_sec,
        },
        output_governance: OutputGovernance {
            deny_patterns: tbs.deny_patterns.clone(),
            redact_patterns: tbs.redact_patterns.clone(),
            max_output_length: tbs.max_output_length,
        },
        jurisdiction: MandateJurisdiction {
            region: tbs.region.clone(),
            regulatory_framework: tbs.regulatory_framework.clone(),
            environment: tbs.environment.clone(),
            classification: tbs.classification.clone(),
            operating_hours: tbs.operating_hours.clone(),
        },
        escalation: EscalationRules {
            escalate_tools: tbs.escalate_tools.clone(),
            escalate_paths: tbs.escalate_paths.clone(),
            escalate_hosts: tbs.escalate_hosts.clone(),
            escalate_to: tbs.escalate_to.clone(),
        },
        signature: None,
    }
}

/// Decode a CBOR mandate envelope without signature verification.
///
/// Used by `decide_core()`: step 0 (revocation check) needs `agent_did` and
/// `mandate_hash` before the step 1 signature verification.
pub fn parse_cbor_mandate_raw(cbor: &[u8]) -> Result<(Mandate, CborMandate), A2gError> {
    let envelope: CborMandate = decode_canonical(cbor)?;
    if envelope.tag.as_str() != "MANDATE-V1" {
        return Err(A2gError::MandateInvalid(format!(
            "expected MANDATE-V1 tag, got '{}'",
            envelope.tag
        )));
    }
    let tbs: MandateTbs = decode_canonical(&envelope.tbs)?;
    if tbs.tag.as_str() != "MANDATE" {
        return Err(A2gError::MandateInvalid(format!(
            "expected MANDATE TBS tag, got '{}'",
            tbs.tag
        )));
    }
    let mandate = tbs_to_mandate(&tbs);
    Ok((mandate, envelope))
}

/// Verify the ed25519 signature on a decoded CBOR mandate envelope.
///
/// Checks:
/// 1. `issuer_pubkey` is a valid 32-byte ed25519 key.
/// 2. `signature` is a valid 64-byte ed25519 signature over `tbs` bytes.
/// 3. `capabilities_hash` in TBS matches the `tools` list.
/// 4. `issuer_did` in TBS matches `did:a2g:<bs58(issuer_pubkey)>`.
pub(crate) fn verify_cbor_signature(envelope: &CborMandate) -> Result<(), A2gError> {
    let tbs: MandateTbs = decode_canonical(&envelope.tbs)?;

    let pubkey_bytes: &[u8] = envelope.issuer_pubkey.as_ref();
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| A2gError::InvalidKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| A2gError::InvalidKey)?;

    let sig_bytes: &[u8] = envelope.signature.as_ref();
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| A2gError::SignatureInvalid)?;
    let sig = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&envelope.tbs, &sig)
        .map_err(|_| A2gError::SignatureInvalid)?;

    // Verify issuer_did matches issuer_pubkey
    let expected_issuer_did = format!("did:a2g:{}", bs58::encode(&pubkey_arr).into_string());
    if tbs.issuer_did != expected_issuer_did {
        return Err(A2gError::MandateInvalid(
            "issuer_did does not match issuer_pubkey".to_string(),
        ));
    }

    // Verify capabilities_hash matches tools (§4.5 canonicalization)
    let expected_hash = capabilities_hash(&tbs.tools);
    let expected_bytes =
        hex::decode(&expected_hash).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let cap_hash_bytes: &[u8] = tbs.capabilities_hash.as_ref();
    if cap_hash_bytes != expected_bytes.as_slice() {
        return Err(A2gError::MandateInvalid(
            "capabilities_hash does not match tools list".to_string(),
        ));
    }

    Ok(())
}

/// Decode and verify a CBOR mandate, checking TTL.
///
/// This is the public verification API for the CLI `a2g verify` command.
pub fn verify_cbor_mandate(cbor: &[u8], now: DateTime<Utc>) -> Result<MandateInfo, A2gError> {
    let (mandate, envelope) = parse_cbor_mandate_raw(cbor)?;
    verify_cbor_signature(&envelope)?;

    let expires_at = mandate
        .mandate
        .expires_at
        .parse::<DateTime<Utc>>()
        .map_err(|_| A2gError::MandateInvalid("invalid expires_at timestamp".to_string()))?;

    let ttl_remaining = expires_at.signed_duration_since(now).num_seconds();
    if ttl_remaining <= 0 {
        return Err(A2gError::MandateExpired);
    }

    Ok(MandateInfo {
        agent_did: mandate.mandate.agent_did,
        agent_name: mandate.mandate.agent_name,
        issuer: mandate.mandate.issuer,
        expires_at: expires_at.to_rfc3339(),
        ttl_remaining_sec: ttl_remaining,
        tools: mandate.capabilities.tools,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::panic
    )]
    use super::*;
    use crate::identity;

    /// Helper: compile+sign a mandate template to CBOR bytes for tests.
    /// Mirrors the CLI compile_mandate logic without the toml dep in core.
    /// Tests that need CBOR must use this helper.
    fn compile_test_mandate(tools: Vec<String>, ttl_hours: u64) -> (Vec<u8>, String) {
        use crate::cbor::{encode_canonical, CborMandate, MandateTbs};
        use ed25519_dalek::Signer;

        let (agent_did, _, _) = identity::generate_agent_keypair();
        let (_, sovereign_secret, _) = identity::generate_agent_keypair();
        let secret_bytes = hex::decode(&sovereign_secret).unwrap();
        let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
        let verifying_key = signing_key.verifying_key();

        let now = chrono::Utc::now();
        let expires = now
            .checked_add_signed(chrono::Duration::hours(ttl_hours as i64))
            .unwrap_or(now);
        let issuer_did = format!(
            "did:a2g:{}",
            bs58::encode(verifying_key.to_bytes()).into_string()
        );
        let cap_hash_hex = capabilities_hash(&tools);
        let cap_hash_bytes = hex::decode(&cap_hash_hex).unwrap();

        let tbs = MandateTbs {
            tag: "MANDATE".to_string(),
            agent_did: agent_did.clone(),
            issuer_did: issuer_did.clone(),
            agent_name: "test-agent".to_string(),
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            proposal_hash: String::new(),
            workspace_root: String::new(),
            capabilities_hash: cap_hash_bytes.into(),
            tools: tools.clone(),
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
            escalate_tools: vec![],
            escalate_paths: vec![],
            escalate_hosts: vec![],
            escalate_to: String::new(),
        };

        let tbs_bytes = encode_canonical(&tbs).unwrap();
        let sig = signing_key.sign(&tbs_bytes);
        let envelope = CborMandate {
            tag: "MANDATE-V1".to_string(),
            tbs: tbs_bytes.into(),
            signature: sig.to_bytes().to_vec().into(),
            issuer_pubkey: verifying_key.to_bytes().to_vec().into(),
        };
        let cbor = encode_canonical(&envelope).unwrap();
        (cbor, sovereign_secret)
    }

    #[test]
    fn test_sign_and_verify() {
        let tools = vec!["read_file".to_string(), "write_file".to_string()];
        let (cbor, _) = compile_test_mandate(tools, 24);
        let info = verify_cbor_mandate(&cbor, chrono::Utc::now()).unwrap();
        assert_eq!(info.agent_name, "test-agent");
        assert!(info.ttl_remaining_sec > 0);
    }

    #[test]
    fn test_template_generation() {
        let template = generate_template("my-agent", "did:a2g:test123");
        assert!(template.contains("my-agent"));
        assert!(template.contains("did:a2g:test123"));
    }

    /// Pin the capabilities_hash algorithm so a serializer change cannot silently
    /// drift the signing payload (§4.5 normative rule, ADR-0013).
    #[test]
    fn test_capabilities_hash_exact_bytes() {
        let tools = vec![
            "vehicle.door.unlock".to_string(),
            "vehicle.climate.set_temperature".to_string(),
        ];
        let expected_joined = "vehicle.climate.set_temperature\nvehicle.door.unlock";
        let expected = hex::encode(Sha256::digest(expected_joined.as_bytes()));
        assert_eq!(
            capabilities_hash(&tools),
            expected,
            "capabilities_hash algorithm has drifted from SPEC §4.5"
        );
    }

    #[test]
    fn test_capabilities_hash_sort_order() {
        let unsorted = vec![
            "z_tool".to_string(),
            "a_tool".to_string(),
            "m_tool".to_string(),
        ];
        let sorted = vec![
            "a_tool".to_string(),
            "m_tool".to_string(),
            "z_tool".to_string(),
        ];
        assert_eq!(capabilities_hash(&unsorted), capabilities_hash(&sorted));
    }

    #[test]
    fn test_capabilities_hash_empty() {
        let expected = hex::encode(Sha256::digest(b""));
        assert_eq!(capabilities_hash(&[]), expected);
    }

    #[test]
    fn test_cbor_mandate_round_trip() {
        let tools = vec!["read_file".to_string()];
        let (cbor, _) = compile_test_mandate(tools.clone(), 24);
        let (mandate, envelope) = parse_cbor_mandate_raw(&cbor).unwrap();
        verify_cbor_signature(&envelope).unwrap();
        assert_eq!(mandate.capabilities.tools, tools);
    }

    #[test]
    fn test_malformed_cbor_mandate_rejected() {
        let result = parse_cbor_mandate_raw(b"not cbor");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_signature_rejected() {
        use crate::cbor::{decode_canonical, encode_canonical, CborMandate};
        let tools = vec!["read_file".to_string()];
        let (cbor, _) = compile_test_mandate(tools, 24);
        let mut envelope: CborMandate = decode_canonical(&cbor).unwrap();
        let mut sig = envelope.signature.to_vec();
        sig[0] = if sig[0] == 0x00 { 0xff } else { 0x00 };
        envelope.signature = sig.into();
        let tampered = encode_canonical(&envelope).unwrap();
        let (_, envelope2) = parse_cbor_mandate_raw(&tampered).unwrap();
        assert!(verify_cbor_signature(&envelope2).is_err());
    }
}
