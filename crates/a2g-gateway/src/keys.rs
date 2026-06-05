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
    };

    if let Err(e) = std::fs::write(demo_key_path, serde_json::to_string_pretty(&demo).unwrap()) {
        eprintln!(
            "[gateway:keys] WARNING: could not write demo key file to {}: {e}",
            demo_key_path.display()
        );
    }

    (keys, demo)
}
