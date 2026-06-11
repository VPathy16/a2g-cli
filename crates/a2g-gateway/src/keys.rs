//! Demo key management for the A2G Enforcing Gateway.
//!
//! ╔══════════════════════════════════════════════════════════════════════╗
//! ║  DEMO KEY MANAGEMENT — NOT PRODUCTION KEY MANAGEMENT               ║
//! ║                                                                      ║
//! ║  All keys are ephemeral: generated at gateway startup, held only    ║
//! ║  in memory, discarded on shutdown. No HSM, no key continuity,       ║
//! ║  no rotation, no revocation.                                         ║
//! ║                                                                      ║
//! ║  Private keys for the attester and operator roles are written to a  ║
//! ║  plaintext JSON file so the demo script can sign vehicle state and  ║
//! ║  approval grants. In production, those keys live in separate secure ║
//! ║  enclaves and never appear in the gateway's address space.          ║
//! ╚══════════════════════════════════════════════════════════════════════╝

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// All keys the gateway holds internally.
/// The binding key is never shared. Other private keys are demo-only.
pub struct GatewayKeys {
    /// Signs `PendingApprovalBinding` blobs (gateway's own key; never shared).
    pub binding_signing_key: SigningKey,
    /// Verifies incoming `GatewayReceipt` signatures from the rich domain.
    pub receipt_verifying_key: VerifyingKey,
    /// Verifies `AttestedVehicleState` from the ECU / HAL sensor source.
    pub attester_verifying_key: VerifyingKey,
    /// Verifies `ApprovalGrant` signatures from the human operator.
    pub operator_verifying_key: VerifyingKey,
}

/// Demo-only private key bundle written to disk so the rich domain and demo
/// scripts can sign receipts, vehicle state, and approval grants.
///
/// ⚠ DEMO ONLY — these private keys are ephemeral, plaintext, and disposable.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DemoKeys {
    pub warning: String,
    /// Rich domain uses this to sign `GatewayReceipt` structs.
    pub receipt_signing_key_hex: String,
    /// Simulated ECU uses this to sign `AttestedVehicleState`.
    pub attester_signing_key_hex: String,
    /// Simulated operator uses this to sign `ApprovalGrant`.
    pub operator_signing_key_hex: String,
    /// Public keys (for reference / client bootstrap without reading the file).
    pub receipt_verifying_key_hex: String,
    pub attester_verifying_key_hex: String,
    pub operator_verifying_key_hex: String,
    /// Gateway's binding *verifying* key. The rich domain uses this to verify
    /// gateway-signed bindings at Phase 2 (ADR-0015). The signing half never
    /// leaves the gateway.
    #[serde(default)]
    pub binding_verifying_key_hex: String,
}

impl DemoKeys {
    /// Restore a `SigningKey` from the hex-encoded receipt signing key.
    pub fn receipt_signing_key(&self) -> SigningKey {
        signing_key_from_hex(&self.receipt_signing_key_hex)
    }
    /// Restore a `SigningKey` from the hex-encoded attester signing key.
    pub fn attester_signing_key(&self) -> SigningKey {
        signing_key_from_hex(&self.attester_signing_key_hex)
    }
    /// Restore a `SigningKey` from the hex-encoded operator signing key.
    pub fn operator_signing_key(&self) -> SigningKey {
        signing_key_from_hex(&self.operator_signing_key_hex)
    }
}

fn signing_key_from_hex(hex: &str) -> SigningKey {
    let bytes: [u8; 32] = ::hex::decode(hex)
        .expect("invalid key hex")
        .try_into()
        .expect("key must be 32 bytes");
    SigningKey::from_bytes(&bytes)
}

/// Generate all gateway keys and the demo key bundle.
/// The binding key is returned only inside `GatewayKeys`; its private material
/// is never written to the demo file.
pub fn generate(demo_key_path: &Path) -> (GatewayKeys, DemoKeys) {
    // Gateway internal keys
    let binding_signing_key = SigningKey::generate(&mut OsRng);
    let binding_verifying_key = binding_signing_key.verifying_key();

    // Receipt key — private half goes to demo file, public half stays in gateway
    let receipt_signing_key = SigningKey::generate(&mut OsRng);
    let receipt_verifying_key = receipt_signing_key.verifying_key();

    // Attester key — simulated ECU
    let attester_signing_key = SigningKey::generate(&mut OsRng);
    let attester_verifying_key = attester_signing_key.verifying_key();

    // Operator key — simulated human approver
    let operator_signing_key = SigningKey::generate(&mut OsRng);
    let operator_verifying_key = operator_signing_key.verifying_key();

    let keys = GatewayKeys {
        binding_signing_key,
        receipt_verifying_key,
        attester_verifying_key,
        operator_verifying_key,
    };

    let demo = DemoKeys {
        warning: "DEMO ONLY — NOT PRODUCTION KEY MANAGEMENT. \
                  Private keys are ephemeral and plaintext. \
                  Do not use in production."
            .to_string(),
        receipt_signing_key_hex: hex::encode(receipt_signing_key.to_bytes()),
        attester_signing_key_hex: hex::encode(attester_signing_key.to_bytes()),
        operator_signing_key_hex: hex::encode(operator_signing_key.to_bytes()),
        receipt_verifying_key_hex: hex::encode(receipt_verifying_key.to_bytes()),
        attester_verifying_key_hex: hex::encode(attester_verifying_key.to_bytes()),
        operator_verifying_key_hex: hex::encode(operator_verifying_key.to_bytes()),
        binding_verifying_key_hex: hex::encode(binding_verifying_key.to_bytes()),
    };

    if let Err(e) = std::fs::write(demo_key_path, serde_json::to_string_pretty(&demo).unwrap()) {
        eprintln!(
            "[gateway:keys] WARNING: could not write demo key file to {}: {e}",
            demo_key_path.display()
        );
    }

    (keys, demo)
}

// ── Production keystore (ADR-0015; SPEC §10.1 Level 3) ───────────────────────

/// On-disk keystore for `--production` startup. Holds the gateway's private
/// binding-signing key and the verifying keys it must trust. The receipt,
/// attester, and operator *signing* keys are NOT in this file — they belong to
/// other parties and never enter the gateway's address space.
#[derive(Serialize, Deserialize)]
pub struct ProductionKeystore {
    /// Hex 32-byte ed25519 seed for the gateway's binding-signing key.
    pub binding_signing_key_hex: String,
    /// Hex 32-byte ed25519 public key of the rich domain's receipt signer.
    pub receipt_verifying_key_hex: String,
    /// Hex 32-byte ed25519 public key of the ECU/HAL state attester.
    pub attester_verifying_key_hex: String,
    /// Hex 32-byte ed25519 public key of the human operator.
    pub operator_verifying_key_hex: String,
}

/// Load gateway keys from a provisioned keystore file.
///
/// Returns `Err` with a human-readable reason on any failure — the caller
/// (production startup) MUST refuse to start in that case (SPEC §10.1 Level 3:
/// "Refuses to start in production mode without a properly provisioned key store").
pub fn load_production(keystore_path: &Path) -> Result<GatewayKeys, String> {
    let raw = std::fs::read_to_string(keystore_path)
        .map_err(|e| format!("cannot read keystore {}: {e}", keystore_path.display()))?;
    let ks: ProductionKeystore =
        serde_json::from_str(&raw).map_err(|e| format!("malformed keystore JSON: {e}"))?;

    let binding_signing_key = parse_signing_key(&ks.binding_signing_key_hex)
        .map_err(|e| format!("binding_signing_key_hex: {e}"))?;
    let receipt_verifying_key = parse_verifying_key(&ks.receipt_verifying_key_hex)
        .map_err(|e| format!("receipt_verifying_key_hex: {e}"))?;
    let attester_verifying_key = parse_verifying_key(&ks.attester_verifying_key_hex)
        .map_err(|e| format!("attester_verifying_key_hex: {e}"))?;
    let operator_verifying_key = parse_verifying_key(&ks.operator_verifying_key_hex)
        .map_err(|e| format!("operator_verifying_key_hex: {e}"))?;

    Ok(GatewayKeys {
        binding_signing_key,
        receipt_verifying_key,
        attester_verifying_key,
        operator_verifying_key,
    })
}

fn parse_signing_key(hex_str: &str) -> Result<SigningKey, String> {
    let bytes: [u8; 32] = ::hex::decode(hex_str)
        .map_err(|e| format!("invalid hex: {e}"))?
        .try_into()
        .map_err(|_| "key must be exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = ::hex::decode(hex_str)
        .map_err(|e| format!("invalid hex: {e}"))?
        .try_into()
        .map_err(|_| "key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("not a valid ed25519 point: {e}"))
}
