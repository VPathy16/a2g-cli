//! Mandate — Canonical policy documents with ed25519 signing and TTL
//!
//! A Mandate is a TOML document that declares an agent's permissions.
//! It is signed by a sovereign authority and has a time-to-live (TTL).

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Parsed mandate structure (matches the TOML schema)
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

/// Jurisdictional binding — where and when this mandate is valid
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct MandateJurisdiction {
    /// Geographic region (e.g., "US", "CA", "EU")
    #[serde(default)]
    pub region: String,
    /// Regulatory framework (e.g., "GDPR", "SOC2", "PIPEDA")
    #[serde(default)]
    pub regulatory_framework: String,
    /// Environment constraint (e.g., "production", "staging", "development")
    #[serde(default)]
    pub environment: String,
    /// Classification level (e.g., "public", "internal", "confidential")
    #[serde(default)]
    pub classification: String,
    /// Operating hours in UTC (empty = 24/7, format: "HH:MM-HH:MM")
    #[serde(default)]
    pub operating_hours: String,
}

/// Escalation rules — when to ESCALATE instead of ALLOW
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct EscalationRules {
    /// Tools that trigger ESCALATE instead of ALLOW
    #[serde(default)]
    pub escalate_tools: Vec<String>,
    /// Path patterns that trigger ESCALATE
    #[serde(default)]
    pub escalate_paths: Vec<String>,
    /// Network patterns that trigger ESCALATE
    #[serde(default)]
    pub escalate_hosts: Vec<String>,
    /// DID of the authority to escalate to
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

/// Sanitize an agent name: strip control characters, cap length
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).take(256).collect();
    cleaned
}

/// Generate a mandate template for a new agent
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

/// Compute the `capabilities_hash` component of the canonical signing payload.
///
/// **Algorithm (SPEC §4.5):**
/// 1. Sort `tools` lexicographically (ascending byte order of UTF-8 strings).
/// 2. Join with U+000A NEWLINE (`\n`). Empty list → empty string.
/// 3. SHA-256 of the UTF-8 bytes of the joined string.
/// 4. Hex-encode the digest (lowercase).
///
/// This exact procedure is normative — changing the sort order, separator, or
/// hash algorithm produces a different value and breaks all existing signatures.
pub fn capabilities_hash(tools: &[String]) -> String {
    let mut sorted = tools.to_vec();
    sorted.sort();
    let joined = sorted.join("\n");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

/// Construct the canonical mandate signing payload (SPEC §4.5).
///
/// ```text
/// MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>
/// ```
///
/// The `MANDATE:` domain-separation prefix ensures this payload cannot be valid
/// in any other A2G signing context. The signer and verifier both call this
/// function so the payload is never assembled independently in two places.
pub fn mandate_signing_payload(
    agent_did: &str,
    issuer_did: &str,
    expires_at: &str,
    tools: &[String],
) -> String {
    format!(
        "MANDATE:{}:{}:{}:{}",
        agent_did,
        issuer_did,
        expires_at,
        capabilities_hash(tools)
    )
}

/// Sign a mandate with a sovereign ed25519 key
pub fn sign_mandate(
    mandate_str: &str,
    sovereign_secret_hex: &str,
    ttl_hours: u64,
) -> Result<String, A2gError> {
    // Parse to validate structure
    let mut mandate: Mandate =
        toml::from_str(mandate_str).map_err(|e| A2gError::MandateParse(e.to_string()))?;

    // Set timestamps
    let now = Utc::now();
    let ttl_hours_i64 = i64::try_from(ttl_hours).unwrap_or(i64::MAX);
    let expires = now
        .checked_add_signed(Duration::hours(ttl_hours_i64))
        .unwrap_or(now);
    mandate.mandate.issued_at = now.to_rfc3339();
    mandate.mandate.expires_at = expires.to_rfc3339();

    // Derive issuer DID from sovereign key
    let secret_bytes =
        hex::decode(sovereign_secret_hex).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let secret_arr: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| A2gError::InvalidKey)?;
    let signing_key = SigningKey::from_bytes(&secret_arr);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey_hex = hex::encode(verifying_key.to_bytes());
    let issuer_did = format!(
        "did:a2g:{}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    mandate.mandate.issuer = issuer_did;

    // Build canonical signing payload (SPEC §4.5):
    //   MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>
    let payload = mandate_signing_payload(
        &mandate.mandate.agent_did,
        &mandate.mandate.issuer,
        &mandate.mandate.expires_at,
        &mandate.capabilities.tools,
    );
    let body_hash = Sha256::digest(payload.as_bytes());
    let signature = signing_key.sign(&body_hash);

    // Remove old signature before serializing the TOML body
    mandate.signature = None;
    let body_str = toml::to_string_pretty(&mandate).map_err(|e| A2gError::Json(e.to_string()))?;

    // Build final TOML with signature section
    let signed_toml = format!(
        "{}\n[signature]\nalgorithm = \"ed25519\"\nissuer_pubkey = \"{}\"\nsignature = \"{}\"\nsigned_at = \"{}\"\n",
        body_str.trim(),
        issuer_pubkey_hex,
        hex::encode(signature.to_bytes()),
        now.to_rfc3339()
    );

    Ok(signed_toml)
}

/// Verify a signed mandate — checks signature, TTL, and structural validity
pub fn verify_mandate(mandate_str: &str) -> Result<MandateInfo, A2gError> {
    let mandate: Mandate =
        toml::from_str(mandate_str).map_err(|e| A2gError::MandateParse(e.to_string()))?;

    // 1. Check signature exists
    let sig = mandate
        .signature
        .as_ref()
        .ok_or_else(|| A2gError::MandateInvalid("mandate is unsigned".to_string()))?;

    // 2. Verify signature algorithm
    if sig.algorithm != "ed25519" {
        return Err(A2gError::MandateInvalid(format!(
            "unsupported algorithm: {}",
            sig.algorithm
        )));
    }

    // 3. Reconstruct canonical signing payload for verification (SPEC §4.5)
    let mut verify_mandate = mandate;
    let sig_clone = verify_mandate
        .signature
        .take()
        .ok_or_else(|| A2gError::Internal("mandate signature unexpectedly absent".to_string()))?;
    let payload = mandate_signing_payload(
        &verify_mandate.mandate.agent_did,
        &verify_mandate.mandate.issuer,
        &verify_mandate.mandate.expires_at,
        &verify_mandate.capabilities.tools,
    );
    let body_hash = Sha256::digest(payload.as_bytes());

    // 4. Verify ed25519 signature
    let pubkey_bytes =
        hex::decode(&sig_clone.issuer_pubkey).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| A2gError::InvalidKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| A2gError::InvalidKey)?;

    let sig_bytes =
        hex::decode(&sig_clone.signature).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| A2gError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&body_hash, &signature)
        .map_err(|_| A2gError::SignatureInvalid)?;

    // 5. Check TTL
    let expires_at = verify_mandate
        .mandate
        .expires_at
        .parse::<DateTime<Utc>>()
        .map_err(|_| A2gError::MandateInvalid("invalid expires_at timestamp".to_string()))?;

    let now = Utc::now();
    let ttl_remaining = expires_at.signed_duration_since(now).num_seconds();

    if ttl_remaining <= 0 {
        return Err(A2gError::MandateExpired);
    }

    // 6. Return info
    Ok(MandateInfo {
        agent_did: verify_mandate.mandate.agent_did,
        agent_name: verify_mandate.mandate.agent_name,
        issuer: verify_mandate.mandate.issuer,
        expires_at: expires_at.to_rfc3339(),
        ttl_remaining_sec: ttl_remaining,
        tools: verify_mandate.capabilities.tools,
    })
}

/// Verify only the ed25519 signature on a mandate — no TTL check.
///
/// Used by `decide()` so that the TTL check can be performed with an
/// injected clock rather than `Utc::now()` called inside here.
pub fn verify_signature(mandate_str: &str) -> Result<(), A2gError> {
    let mandate: Mandate =
        toml::from_str(mandate_str).map_err(|e| A2gError::MandateParse(e.to_string()))?;
    let sig = mandate
        .signature
        .as_ref()
        .ok_or_else(|| A2gError::MandateInvalid("mandate is unsigned".to_string()))?;
    if sig.algorithm != "ed25519" {
        return Err(A2gError::MandateInvalid(format!(
            "unsupported algorithm: {}",
            sig.algorithm
        )));
    }
    let mut m = mandate;
    let sig_clone = m
        .signature
        .take()
        .ok_or_else(|| A2gError::Internal("mandate signature unexpectedly absent".to_string()))?;
    let payload = mandate_signing_payload(
        &m.mandate.agent_did,
        &m.mandate.issuer,
        &m.mandate.expires_at,
        &m.capabilities.tools,
    );
    let body_hash = Sha256::digest(payload.as_bytes());
    let pubkey_bytes =
        hex::decode(&sig_clone.issuer_pubkey).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| A2gError::InvalidKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| A2gError::InvalidKey)?;
    let sig_bytes =
        hex::decode(&sig_clone.signature).map_err(|e| A2gError::HexDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| A2gError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&body_hash, &signature)
        .map_err(|_| A2gError::SignatureInvalid)?;
    Ok(())
}

/// Parse a mandate from TOML string
pub fn parse_mandate(mandate_str: &str) -> Result<Mandate, A2gError> {
    let mandate: Mandate =
        toml::from_str(mandate_str).map_err(|e| A2gError::MandateParse(e.to_string()))?;
    Ok(mandate)
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

    #[test]
    fn test_sign_and_verify() {
        let (did, _, _) = identity::generate_agent_keypair();
        let (_, sovereign_secret, _) = identity::generate_agent_keypair();

        let template = generate_template("test-agent", &did);
        let signed = sign_mandate(&template, &sovereign_secret, 24).unwrap();
        let info = verify_mandate(&signed).unwrap();

        assert_eq!(info.agent_name, "test-agent");
        assert_eq!(info.agent_did, did);
        assert!(info.ttl_remaining_sec > 0);
    }

    #[test]
    fn test_template_generation() {
        let template = generate_template("my-agent", "did:a2g:test123");
        assert!(template.contains("my-agent"));
        assert!(template.contains("did:a2g:test123"));
    }

    /// Asserts the exact byte layout of the canonical signing payload so a future
    /// serializer or formatting change cannot silently drift from SPEC §4.5.
    ///
    /// Payload: `MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>`
    /// capabilities_hash: SHA-256(tools sorted lexicographically, joined with `\n`)
    #[test]
    fn test_signing_payload_exact_bytes() {
        // Fixed inputs — do not change without bumping the mandate schema version.
        let agent_did = "did:a2g:AgentAAA";
        let issuer_did = "did:a2g:IssuerBBB";
        let expires_at = "2099-01-01T00:00:00Z";
        let tools = vec![
            "vehicle.door.unlock".to_string(),
            "vehicle.climate.set_temperature".to_string(),
        ];

        // Sorted lexicographically:
        //   vehicle.climate.set_temperature
        //   vehicle.door.unlock
        // Joined with \n:
        //   "vehicle.climate.set_temperature\nvehicle.door.unlock"
        let expected_joined = "vehicle.climate.set_temperature\nvehicle.door.unlock";
        let expected_cap_hash = hex::encode(Sha256::digest(expected_joined.as_bytes()));

        let expected_payload = format!(
            "MANDATE:{}:{}:{}:{}",
            agent_did, issuer_did, expires_at, expected_cap_hash
        );

        let actual_payload = mandate_signing_payload(agent_did, issuer_did, expires_at, &tools);

        assert_eq!(
            actual_payload, expected_payload,
            "Signing payload byte layout has drifted from SPEC §4.5. \
             Changing this is a breaking protocol change — update CHANGELOG."
        );

        // Also assert capabilities_hash directly.
        assert_eq!(capabilities_hash(&tools), expected_cap_hash);
    }

    #[test]
    fn test_capabilities_hash_sort_order() {
        // Unsorted input must produce the same hash as sorted input.
        let tools_unsorted = vec![
            "z_tool".to_string(),
            "a_tool".to_string(),
            "m_tool".to_string(),
        ];
        let tools_sorted = vec![
            "a_tool".to_string(),
            "m_tool".to_string(),
            "z_tool".to_string(),
        ];
        assert_eq!(
            capabilities_hash(&tools_unsorted),
            capabilities_hash(&tools_sorted)
        );
    }

    #[test]
    fn test_capabilities_hash_empty() {
        // Empty capability list: SHA-256 of "" (empty string).
        let expected = hex::encode(Sha256::digest(b""));
        assert_eq!(capabilities_hash(&[]), expected);
    }
}
