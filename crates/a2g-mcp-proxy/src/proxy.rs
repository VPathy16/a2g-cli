//! Proxy dispatch loop.
//!
//! Reads JSON-RPC messages from upstream (the LLM / agent harness) and:
//!   - Forwards `initialize`, `initialized`, `tools/list` transparently.
//!   - Intercepts `tools/call`, applies A2G governance, and only forwards
//!     when the gateway accepts the receipt.
//!
//! The loop runs until upstream closes its stdin.

use std::io::{self, BufReader, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::config::ProxyConfig;
use crate::governance::{GovernanceContext, GovernanceOutcome};
use crate::mcp::{
    err_response, read_message, write_response, JsonRpcRequest, JsonRpcResponse, ERR_A2G_DENIED,
    ERR_A2G_ESCALATE, ERR_A2G_GATEWAY, ERR_A2G_INTERNAL,
};
use crate::transport::{call_downstream, DownstreamTransport};

/// Run the proxy dispatch loop.
///
/// Reads from `upstream_in`, writes to `upstream_out`.
/// Uses `downstream` for the downstream MCP server.
/// `config` provides the tool map and gateway socket path.
/// `gov` is the pre-loaded governance context.
pub fn run_proxy<In, Out>(
    upstream_in: In,
    upstream_out: &mut Out,
    downstream: &mut dyn DownstreamTransport,
    config: &ProxyConfig,
    gov: &GovernanceContext,
) where
    In: io::Read,
    Out: Write,
{
    let mut reader = BufReader::new(upstream_in);

    loop {
        let raw = match read_message(&mut reader) {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Upstream closed stdin — clean shutdown.
                break;
            }
            Err(e) => {
                eprintln!("[a2g-mcp-proxy] framing error: {e}");
                break;
            }
        };

        let req: JsonRpcRequest = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[a2g-mcp-proxy] JSON parse error: {e}");
                // Cannot send error without an id; skip.
                continue;
            }
        };

        let id = req.id.clone().unwrap_or(Value::Null);
        let method = req.method.as_str();

        let response = match method {
            // ── Passthrough: initialize ────────────────────────────────────
            "initialize" => match call_downstream(downstream, &req) {
                Ok(resp) => resp,
                Err(e) => {
                    err_response(id, ERR_A2G_INTERNAL, format!("downstream error: {e}"), None)
                }
            },

            // ── Passthrough: initialized (notification, no response needed) ─
            "notifications/initialized" | "initialized" => {
                // Forward to downstream; no response to upstream for notifications.
                if let Err(e) = {
                    let body = serde_json::to_string(&req).unwrap_or_default();
                    downstream.send(&body)
                } {
                    eprintln!("[a2g-mcp-proxy] forward initialized error: {e}");
                }
                continue;
            }

            // ── Passthrough: tools/list ────────────────────────────────────
            "tools/list" => match call_downstream(downstream, &req) {
                Ok(resp) => resp,
                Err(e) => {
                    err_response(id, ERR_A2G_INTERNAL, format!("downstream error: {e}"), None)
                }
            },

            // ── Governed: tools/call ───────────────────────────────────────
            "tools/call" => handle_tool_call(req, id, downstream, config, gov),

            // ── Passthrough: all other methods ─────────────────────────────
            _ => match call_downstream(downstream, &req) {
                Ok(resp) => resp,
                Err(e) => {
                    err_response(id, ERR_A2G_INTERNAL, format!("downstream error: {e}"), None)
                }
            },
        };

        if let Err(e) = write_response(upstream_out, &response) {
            eprintln!("[a2g-mcp-proxy] write response error: {e}");
            break;
        }
    }
}

// ── tools/call handler ────────────────────────────────────────────────────────

fn handle_tool_call(
    req: JsonRpcRequest,
    id: Value,
    downstream: &mut dyn DownstreamTransport,
    config: &ProxyConfig,
    gov: &GovernanceContext,
) -> JsonRpcResponse {
    // Extract tool name from params.
    let params = req.params.as_ref().cloned().unwrap_or(json!({}));
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

    // Map tool name → A2G capability (fail-closed: unmapped → "unmapped.<tool>").
    let capability = config.resolve_capability(tool_name);

    // Params for decide() — use the tool "arguments" sub-object if present.
    let tool_args: Value = params.get("arguments").cloned().unwrap_or(json!({}));
    let tool_args_json = serde_json::to_string(&tool_args).unwrap_or_else(|_| "{}".to_string());

    eprintln!("[a2g-mcp-proxy] tool_call tool={tool_name:?} capability={capability:?}");

    // ── A2G governance check ───────────────────────────────────────────────
    let outcome = gov.check(
        &capability,
        &tool_args,
        &tool_args_json,
        Path::new(&config.gateway_socket),
    );

    match outcome {
        GovernanceOutcome::Allow { receipt_id } => {
            // Forward to downstream and return result with receipt_id in _meta.
            eprintln!("[a2g-mcp-proxy] ALLOW receipt_id={receipt_id} — forwarding downstream");
            match call_downstream(downstream, &req) {
                Ok(mut resp) => {
                    // Inject receipt_id into result._meta.
                    if let Some(ref mut result) = resp.result {
                        if let Some(obj) = result.as_object_mut() {
                            obj.insert(
                                "_meta".to_string(),
                                json!({ "a2g_receipt_id": receipt_id }),
                            );
                        }
                    } else {
                        // Result was null; replace with meta-only object.
                        resp.result = Some(json!({ "_meta": { "a2g_receipt_id": receipt_id } }));
                    }
                    resp
                }
                Err(e) => err_response(
                    id,
                    ERR_A2G_INTERNAL,
                    format!("downstream error after ALLOW: {e}"),
                    None,
                ),
            }
        }

        GovernanceOutcome::Deny {
            reason_code,
            human_text,
        } => {
            eprintln!("[a2g-mcp-proxy] DENY tool={tool_name:?} reason={reason_code}");
            err_response(
                id,
                ERR_A2G_DENIED,
                format!("a2g_denied: {human_text}"),
                Some(json!({
                    "reason_code": reason_code,
                    "tool": tool_name,
                    "capability": capability,
                })),
            )
        }

        GovernanceOutcome::Escalate {
            binding_id,
            escalate_to,
            human_text,
        } => {
            eprintln!("[a2g-mcp-proxy] ESCALATE tool={tool_name:?} binding_id={binding_id}");
            err_response(
                id,
                ERR_A2G_ESCALATE,
                format!(
                    "a2g_escalate: human-in-the-loop approval required; \
                     retry after approval with binding_id={binding_id}"
                ),
                Some(json!({
                    "binding_id": binding_id,
                    "escalate_to": escalate_to,
                    "human_text": human_text,
                    "tool": tool_name,
                    "capability": capability,
                })),
            )
        }

        GovernanceOutcome::GatewayRefused { reason } => {
            eprintln!("[a2g-mcp-proxy] GATEWAY_REFUSED tool={tool_name:?} reason={reason}");
            err_response(
                id,
                ERR_A2G_GATEWAY,
                format!("a2g_gateway_refused: {reason}"),
                Some(json!({
                    "reason": reason,
                    "tool": tool_name,
                    "capability": capability,
                })),
            )
        }

        GovernanceOutcome::InternalError { message } => {
            eprintln!("[a2g-mcp-proxy] INTERNAL_ERROR tool={tool_name:?} msg={message}");
            err_response(
                id,
                ERR_A2G_INTERNAL,
                format!("a2g_internal_error: {message}"),
                Some(json!({
                    "message": message,
                    "tool": tool_name,
                })),
            )
        }
    }
}
