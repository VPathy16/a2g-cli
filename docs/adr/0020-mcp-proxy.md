# ADR-0020 — A2G MCP Proxy: Model Context Protocol Governance Wrapper

**Status:** Accepted  
**Date:** 2026-06-12  
**Replaces:** —  
**Related:** ADR-0010 (enforcing gateway), ADR-0012 (A2gError), ADR-0014 (issuer trust),
ADR-0015 (binding key custody), ADR-0018 (cockpit domains), ADR-0019 (QNX portability), SPEC §1.3

---

## Context

MCP (Model Context Protocol) has emerged as a dominant wire format for
LLM-to-tool communication.  An AI agent running over an MCP tool server
has the same principal-of-concern as the A2G Proposer role: it invokes
capabilities that may affect real resources (files, APIs, vehicle subsystems,
payment systems).

Without A2G governance, every tool call from an LLM reaches the downstream
server regardless of mandate, vehicle state, jurisdiction, or human-in-the-loop
requirements.  The MCP protocol itself has no authorization layer.

### Threat model

The proxy runs in the **rich domain** — the same trust tier as the CLI and
the demo harness.  It can lie.  The Enforcing Gateway remains the sole
enforcement point for all vehicle-bus and cockpit-sensitive actions.  The
proxy's role is:

1. **Pre-flight governance**: call `decide()` before forwarding any tool call.
2. **Gateway enforcement**: for ALLOW verdicts, present the signed receipt to
   the gateway ENFORCE endpoint and forward only if the gateway accepts.
3. **Fail-closed on DENY / ESCALATE**: return a structured MCP error; the
   downstream server MUST NOT see the call.

Because the proxy is rich-domain, a compromised proxy cannot bypass the
gateway's independent 7-step verification (ADR-0010).  The gateway re-checks
forbidden domains, re-verifies the receipt signature, re-verifies freshness,
and re-checks the anti-replay nonce ring — independent of anything the proxy
claims.

---

## Decision

### New crate: `a2g-mcp-proxy`

A standalone Rust binary that:

1. Reads a TOML config on startup (never signed — authoring-side only):
   - Downstream server `command` + `args`.
   - Path to a CBOR mandate file.
   - Gateway Unix socket path.
   - TrustAnchor source (self-sovereign for now; root keys extension-point).
   - `[tool_map]` table: `tool_name = "capability_name"`.
   - Default rule: **any unmapped tool → Sensitive-with-HITL** (fail-closed).

2. Speaks the MCP JSON-RPC 2.0 stdio protocol on its own stdin/stdout,
   acting as an MCP server to the upstream caller (the LLM / agent harness).

3. Spawns the downstream MCP server as a child process, forwarding only:
   - `initialize` / `initialized` handshake.
   - `tools/list` (proxied transparently).
   - `tools/call` — **subject to A2G governance before forwarding**.

4. For every `tools/call`:
   a. Map tool name → A2G capability via config table.
      Unmapped → synthetic capability `unmapped.<tool_name>` (not in any mandate → DENY,
      fail-closed; audit trail records the real tool name, not a payment namespace).
   b. Call `a2g_core::enforce::decide()` with the mandate + TrustAnchor.
   c. On **DENY / EXPIRED**: return MCP error `{"code": -32001, ...}` with
      machine reason code and human-readable text.  Downstream never called.
   d. On **PENDING_APPROVAL (ESCALATE)**: return MCP error `{"code": -32002, ...}`
      instructing retry-after-approval, including `binding_id`.
      Present the binding to the gateway `SignBinding` endpoint so the operator
      can approve.  Downstream never called.
   e. On **ALLOW**: sign a `GatewayReceipt` and send it to the gateway
      `Enforce` endpoint.  Only on `GatewayResponse::Enforced` does the
      proxy forward the call downstream and return the result with
      `receipt_id` in the response `_meta` field.
      On any other gateway response, return MCP error `{"code": -32003, ...}`.

5. Transport: **stdio only** for this task.  A `DownstreamTransport` trait
   provides a seam for HTTP/SSE later (currently `unimplemented!()`).

### Trust notes (rich-domain)

The proxy runs in the rich domain and can be compromised.  This is explicitly
documented and acceptable because:

- The gateway's 7-step verification (ADR-0010) is independent and cannot be
  bypassed by the proxy.
- The proxy does not hold the gateway's binding-signing key (ADR-0015).
- A receipt signed by a compromised proxy key that is not the gateway-trusted
  receipt verifying key will fail Step 2 of gateway enforcement.
- The only consequence of a compromised proxy is that the gateway may receive
  receipts for calls that were not actually approved — which the gateway
  rejects at Steps 2–7.

### Mandate key flow

For demo / testing the proxy loads the demo key file written by the gateway
at startup and uses the `receipt_signing_key_hex` to sign receipts.  The
mandate file path is configured in TOML; the proxy reads and caches it.

### Fail-closed defaults

| Condition | Action |
|-----------|--------|
| Tool unmapped | Capability becomes `unmapped.<tool_name>` → not in mandate → DENY (`tool_not_authorized`); truthful in audit trail |
| `decide()` returns `Err` | DENY with `internal_error` code |
| Gateway connection fails | MCP error `gateway_unreachable` |
| Gateway returns `Refused` | MCP error `gateway_refused` |
| Gateway returns `Error` | MCP error `gateway_error` |
| Downstream process exits | MCP error `downstream_unavailable` |

---

## Consequences

### Added

- New crate `a2g-mcp-proxy` with binary `a2g-mcp-proxy`.
- Demo config and echo MCP server binary `a2g-echo-mcp-server` for
  quickstart testing.
- E2E tests in `tests/e2e.rs` covering allowed, denied, and unmapped paths.
- README with 10-minute quickstart.

### Not changed

- `a2g-core`: no new dependencies, no public API changes.
- `a2g-gateway`: one justified `pub use` re-export of `client::sign_receipt_with_params`
  and `client::send_request` so the proxy crate does not duplicate the
  receipt-signing and socket-client logic that the demo already uses.
  These were already `pub` inside `pub mod client`; no new public surface is
  added to the gateway crate.
- Protocol is FROZEN: no changes to `MandateTbs`, `CborMandate`, `ReceiptPayload`,
  `GatewayRequest`, or `GatewayResponse`.

### Open questions

- HTTP/SSE transport (ADR future): when the `HttpSseTransport` implementation
  lands, the `DownstreamTransport` trait seam is the integration point.
- Approval UI: ESCALATE returns a binding_id to the caller; an approval UI
  component (browser extension, operator CLI) is out of scope for S2.
