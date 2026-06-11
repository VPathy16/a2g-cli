//! A2G Enforcing Gateway (ADR-0010) — library root.
//!
//! Exposes the server, protocol, and key types for use in integration tests
//! and by the binary entry point.

pub mod bus;
pub mod forbidden;
pub mod keys;
pub mod pending;
pub mod protocol;
pub mod server;
pub mod state_ingest;
pub mod transport;

pub use keys::{DemoKeys, GatewayKeys};
pub use protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};
pub use server::GatewayState;

/// Default vcan interface name for the demo.
pub const DEFAULT_VCAN_IFACE: &str = "vcan0";

/// Default Unix socket path for the gateway.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/a2g-gateway.sock";

/// Default demo key file path.
pub const DEFAULT_DEMO_KEY_PATH: &str = "/tmp/a2g-gateway-demo-keys.json";

/// Convenience: build a signed `GatewayReceipt` from a verdict.
///
/// Used by the rich-domain side (tests and demo script wrappers) to construct
/// a properly-signed receipt that the gateway will accept.
pub mod client {
    use super::protocol::{GatewayReceipt, GatewayRequest, GatewayResponse};
    use super::transport;
    use a2g_core::enforce::Verdict;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    /// Send a single `GatewayRequest` over the socket and return the response.
    ///
    /// Uses length-prefixed CBOR framing (P4 / ADR-0010 §Transport).
    pub fn send_request(socket_path: &Path, req: &GatewayRequest) -> GatewayResponse {
        let stream = UnixStream::connect(socket_path).expect("connect to gateway");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut w = stream.try_clone().unwrap();
        transport::write_frame(&mut w, req).expect("send request frame");

        let mut r = stream;
        transport::read_frame(&mut r).expect("read response frame")
    }

    /// Construct and sign a `GatewayReceipt` from a core `Verdict`.
    pub fn sign_receipt(
        verdict: &Verdict,
        signing_key: &SigningKey,
        attested_state_json: Option<String>,
    ) -> GatewayReceipt {
        let issued_at_ms = Utc::now().timestamp_millis();

        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);

        let binding_id = verdict
            .pending_approval
            .as_ref()
            .map(|_| String::new()) // for Enforce, binding_id comes from the signed blob
            .unwrap_or_default();

        let request_hash = GatewayReceipt::compute_request_hash(
            &verdict.tool,
            // params_json isn't in Verdict; use empty string (must match what decide() received)
            "",
            issued_at_ms,
        );

        let receipt_partial = GatewayReceipt {
            verdict_id: verdict.verdict_id.clone(),
            decision: verdict.decision.to_string(),
            tool: verdict.tool.clone(),
            params_json: String::new(),
            policy_rule: verdict.policy_rule.clone(),
            state_trust: verdict.state_trust.clone(),
            binding_id,
            request_hash,
            issued_at_ms,
            nonce_hex: nonce_hex.clone(),
            signature_hex: String::new(),
            attested_state_json,
        };

        let payload = receipt_partial
            .canonical_bytes()
            .expect("receipt_partial canonical_bytes");
        let sig: ed25519_dalek::Signature = signing_key.sign(&payload);

        GatewayReceipt {
            signature_hex: hex::encode(sig.to_bytes()),
            ..receipt_partial
        }
    }

    /// Construct and sign a receipt with explicit params_json (for request_hash accuracy).
    pub fn sign_receipt_with_params(
        verdict: &Verdict,
        params_json: &str,
        binding_id: &str,
        signing_key: &SigningKey,
        attested_state_json: Option<String>,
    ) -> GatewayReceipt {
        let issued_at_ms = Utc::now().timestamp_millis();

        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);

        let request_hash =
            GatewayReceipt::compute_request_hash(&verdict.tool, params_json, issued_at_ms);

        let receipt_partial = GatewayReceipt {
            verdict_id: verdict.verdict_id.clone(),
            decision: verdict.decision.to_string(),
            tool: verdict.tool.clone(),
            params_json: params_json.to_string(),
            policy_rule: verdict.policy_rule.clone(),
            state_trust: verdict.state_trust.clone(),
            binding_id: binding_id.to_string(),
            request_hash,
            issued_at_ms,
            nonce_hex,
            signature_hex: String::new(),
            attested_state_json,
        };

        let payload = receipt_partial
            .canonical_bytes()
            .expect("receipt_partial canonical_bytes");
        let sig: ed25519_dalek::Signature = signing_key.sign(&payload);

        GatewayReceipt {
            signature_hex: hex::encode(sig.to_bytes()),
            ..receipt_partial
        }
    }
}
