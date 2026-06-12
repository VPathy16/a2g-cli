//! A2G governance bridge for the MCP proxy.
//!
//! Implements the three-phase flow per ADR-0019:
//!
//! 1. `decide()` — pure decision against the loaded mandate.
//! 2. Gateway `Enforce` — present the signed receipt; only on accept do we proceed.
//! 3. Return verdict outcome to the proxy dispatch loop.

use std::path::Path;

use a2g_core::enforce::{decide, Decision, TrustAnchor};
use a2g_core::ledger::NoopLedger;
use a2g_gateway::client::{send_request, sign_receipt_with_params};
use a2g_gateway::keys::DemoKeys;
use a2g_gateway::protocol::{GatewayRequest, GatewayResponse};
use chrono::Utc;
use serde_json::Value;

use crate::config::{ProxyConfig, TrustAnchorConfig};

/// The outcome of a governance check for a single tool call.
#[derive(Debug)]
pub enum GovernanceOutcome {
    /// Call is allowed.  The gateway accepted the receipt.  The receipt verdict_id
    /// is included for embedding in the MCP response `_meta`.
    Allow { receipt_id: String },

    /// Call was denied by `decide()`.
    Deny {
        reason_code: String,
        human_text: String,
    },

    /// Escalation required.  Human-in-the-loop approval must be obtained before
    /// retrying.  `binding_id` is included so the caller can poll for approval.
    Escalate {
        binding_id: String,
        escalate_to: String,
        human_text: String,
    },

    /// Gateway refused or errored after core ALLOW.
    GatewayRefused { reason: String },

    /// Internal error (mandate parse, key load, network, etc.).
    InternalError { message: String },
}

/// Loaded governance context — cached across multiple tool calls.
pub struct GovernanceContext {
    mandate_cbor: Vec<u8>,
    demo_keys: DemoKeys,
    trust_roots: TrustRoots,
}

enum TrustRoots {
    SelfSovereign,
    Roots(Vec<[u8; 32]>),
}

impl GovernanceContext {
    /// Load mandate and demo keys from the paths in `config`.
    pub fn load(config: &ProxyConfig) -> Result<Self, String> {
        let mandate_cbor = std::fs::read(&config.mandate_path)
            .map_err(|e| format!("cannot read mandate {}: {e}", config.mandate_path.display()))?;

        let demo_key_raw = std::fs::read_to_string(&config.demo_key_file).map_err(|e| {
            format!(
                "cannot read demo key file {}: {e}",
                config.demo_key_file.display()
            )
        })?;
        let demo_keys: DemoKeys = serde_json::from_str(&demo_key_raw)
            .map_err(|e| format!("demo key file parse error: {e}"))?;

        let trust_roots = match &config.trust_anchor {
            TrustAnchorConfig::SelfSovereign => TrustRoots::SelfSovereign,
            TrustAnchorConfig::Roots { pubkeys } => {
                let mut roots = Vec::with_capacity(pubkeys.len());
                for pk in pubkeys {
                    let bytes = hex::decode(pk)
                        .map_err(|e| format!("invalid trust root pubkey hex '{pk}': {e}"))?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| format!("trust root pubkey '{pk}' is not 32 bytes"))?;
                    roots.push(arr);
                }
                TrustRoots::Roots(roots)
            }
        };

        Ok(Self {
            mandate_cbor,
            demo_keys,
            trust_roots,
        })
    }

    /// Run the full A2G governance check for a tool call.
    ///
    /// Flow (ADR-0019 §Decision):
    ///   1. `decide()` — pure, no I/O.
    ///   2. On ALLOW: sign receipt → gateway Enforce.
    ///   3. On PENDING_APPROVAL: sign binding → gateway SignBinding; return Escalate.
    ///   4. On DENY/EXPIRED: return Deny without touching downstream or gateway.
    pub fn check(
        &self,
        capability: &str,
        params: &Value,
        params_json: &str,
        gateway_socket: &Path,
    ) -> GovernanceOutcome {
        // ── Step 1: decide() — pure, no I/O ──────────────────────────────────
        let trust: TrustAnchor<'_> = match &self.trust_roots {
            TrustRoots::SelfSovereign => TrustAnchor::SelfSovereign,
            TrustRoots::Roots(roots) => TrustAnchor::Roots(roots.as_slice()),
        };

        let verdict = match decide(
            &self.mandate_cbor,
            capability,
            params,
            &NoopLedger,
            Utc::now(),
            None, // no vehicle state (cockpit proxy path)
            &trust,
        ) {
            Ok(v) => v,
            Err(e) => {
                return GovernanceOutcome::InternalError {
                    message: format!("decide() error: {e}"),
                }
            }
        };

        match &verdict.decision {
            Decision::Allow => {
                // ── Step 2: sign receipt + gateway Enforce ────────────────────
                let signing_key = self.demo_keys.receipt_signing_key();
                let receipt =
                    sign_receipt_with_params(&verdict, params_json, "", &signing_key, None);

                let req = GatewayRequest::Enforce {
                    receipt: Box::new(receipt),
                };
                match send_gateway_request(gateway_socket, &req) {
                    Ok(GatewayResponse::Enforced { verdict_id, .. }) => GovernanceOutcome::Allow {
                        receipt_id: verdict_id,
                    },
                    Ok(GatewayResponse::Refused { reason }) => {
                        GovernanceOutcome::GatewayRefused { reason }
                    }
                    Ok(other) => GovernanceOutcome::GatewayRefused {
                        reason: format!("unexpected gateway response: {other:?}"),
                    },
                    Err(e) => GovernanceOutcome::InternalError {
                        message: format!("gateway_unreachable: {e}"),
                    },
                }
            }

            Decision::Deny | Decision::Expired => GovernanceOutcome::Deny {
                reason_code: slugify(&verdict.policy_rule),
                human_text: verdict.policy_rule.clone(),
            },

            Decision::PendingApproval => {
                // ── Step 3: HITL — sign binding with gateway, return Escalate ─
                let binding = match &verdict.pending_approval {
                    Some(b) => b,
                    None => {
                        return GovernanceOutcome::InternalError {
                            message: "decide() returned PendingApproval without binding"
                                .to_string(),
                        }
                    }
                };
                let binding_id = binding.binding_id.clone();
                let escalate_to = binding.escalate_to.clone();

                // Present binding to gateway for signing/queuing.
                let binding_json = match serde_json::to_string(binding) {
                    Ok(s) => s,
                    Err(e) => {
                        return GovernanceOutcome::InternalError {
                            message: format!("binding serialize error: {e}"),
                        }
                    }
                };

                let req = GatewayRequest::SignBinding { binding_json };
                match send_gateway_request(gateway_socket, &req) {
                    Ok(GatewayResponse::SignedBinding { .. }) => {
                        // Binding is now queued at the gateway.
                        GovernanceOutcome::Escalate {
                            binding_id,
                            escalate_to,
                            human_text: verdict.policy_rule.clone(),
                        }
                    }
                    Ok(GatewayResponse::Error { message }) => GovernanceOutcome::InternalError {
                        message: format!("gateway SignBinding error: {message}"),
                    },
                    Ok(other) => GovernanceOutcome::InternalError {
                        message: format!("unexpected gateway response to SignBinding: {other:?}"),
                    },
                    Err(e) => {
                        // Even if gateway is unreachable, still return Escalate so
                        // the caller knows approval is required — but note the error.
                        eprintln!("[a2g-mcp-proxy] WARN: gateway unreachable for SignBinding: {e}");
                        GovernanceOutcome::Escalate {
                            binding_id,
                            escalate_to,
                            human_text: verdict.policy_rule.clone(),
                        }
                    }
                }
            }
        }
    }
}

/// Send a request to the gateway and return the response.
fn send_gateway_request(
    socket_path: &Path,
    req: &GatewayRequest,
) -> Result<GatewayResponse, String> {
    // send_request panics on connection failure; wrap in a catch.
    std::panic::catch_unwind(|| send_request(socket_path, req))
        .map_err(|_| "gateway connection failed (socket unreachable)".to_string())
}

/// Convert a policy rule string into a machine-readable slug.
/// E.g. "tool_not_authorized: 'foo' not in capabilities.tools" → "tool_not_authorized"
fn slugify(rule: &str) -> String {
    rule.split(':')
        .next()
        .unwrap_or(rule)
        .trim()
        .replace(' ', "_")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_slugify() {
        assert_eq!(
            slugify("tool_not_authorized: 'foo' not in capabilities.tools"),
            "tool_not_authorized"
        );
        assert_eq!(slugify("all_checks_passed"), "all_checks_passed");
        assert_eq!(slugify(""), "");
    }
}
