# a2g-mcp-proxy

A Model Context Protocol (MCP) governance proxy for the A2G protocol.

Wraps any downstream MCP tool server and forces every `tools/call` through A2G
governance before forwarding.  Denied calls never reach the downstream server.

**Design reference:** ADR-0019  
**Protocol version:** A2G v0.2.0 (protocol frozen)

---

## What it does

```
LLM / agent harness
      │  JSON-RPC 2.0 (stdio)
      ▼
 a2g-mcp-proxy  ─── a2g_core::decide() ───► mandate + TrustAnchor
      │                                             │
      │                               ALLOW / DENY / ESCALATE
      │
      │  (only on ALLOW → gateway accept)
      ▼
 a2g-gateway (Unix socket)  ─► 7-step independent verification
      │
      │  (only on Enforced)
      ▼
 downstream MCP server (stdio)
      │
      ▼
 result with receipt_id in _meta
```

For every `tools/call`:

1. The tool name is mapped to an A2G capability via `[tool_map]`.
   Any **unmapped** tool defaults to `pay.unknown` (always-HITL, fail-closed).
2. `a2g_core::decide()` is called with the mandate and TrustAnchor.
3. **DENY / EXPIRED** → MCP error `-32001` (`a2g_denied`). Downstream never called.
4. **PENDING_APPROVAL (ESCALATE)** → MCP error `-32002` (`a2g_escalate`) with
   `binding_id` for retry-after-approval. Downstream never called.
5. **ALLOW** → signed receipt sent to the gateway `Enforce` endpoint.
   - Gateway accept → downstream forwarded; result returned with `receipt_id` in `_meta`.
   - Gateway refuse → MCP error `-32003` (`a2g_gateway_refused`). Downstream not called.

---

## 10-minute quickstart

### Prerequisites

- Rust toolchain (stable, 1.77+)
- The workspace built: `cargo build --workspace`
- Both binaries on your path (or use `cargo run -p ...`):

```bash
# From the workspace root:
cargo build -p a2g-mcp-proxy -p a2g-gateway
export PATH="$PWD/target/debug:$PATH"
```

### Step 1 — Start the gateway

```bash
a2g-gateway \
  --socket-path /tmp/a2g-gateway.sock \
  --demo-key-file /tmp/a2g-gateway-demo-keys.json \
  --vcan vcan0 &
```

Wait for the gateway to print `[gateway] listening on /tmp/a2g-gateway.sock`.

### Step 2 — Issue a demo mandate

The proxy needs a signed mandate that grants the `vehicle.climate.set_temperature`
capability (as mapped in the demo config).

```bash
# The a2g-cli mandate issue command creates a signed CBOR mandate.
# For the quickstart, build a test mandate using the demo key:
a2g-cli mandate issue \
  --agent-name "demo-mcp-agent" \
  --tools "vehicle.climate.set_temperature" \
  --ttl 24h \
  --key-file /tmp/a2g-gateway-demo-keys.json \
  --output /tmp/a2g-demo-mandate.cbor
```

### Step 3 — Run the proxy

```bash
a2g-mcp-proxy --config crates/a2g-mcp-proxy/demo/proxy.toml
```

The proxy reads MCP JSON-RPC from its stdin and writes responses to stdout.

### Step 4 — Send a tool call

In a separate terminal (or from your LLM harness), send a Content-Length–framed
MCP `tools/call` to the proxy's stdin:

```bash
# The proxy is a stdio server. Pipe MCP messages to it.
# Example: call the "echo" tool (mapped to vehicle.climate.set_temperature).
printf 'Content-Length: 120\r\n\r\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}' \
  | a2g-mcp-proxy --config crates/a2g-mcp-proxy/demo/proxy.toml
```

For a full interactive demo, use the `a2g-demo run` command which showcases the
full four-beat governance flow including HITL approval.

### Expected output

A successful `tools/call` for the `echo` tool returns:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "echo: tool=echo arguments=..."}],
    "_meta": {
      "a2g_receipt_id": "<gateway-verdict-uuid>"
    }
  }
}
```

A denied call (tool not in mandate) returns:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "a2g_denied: tool_not_authorized: ...",
    "data": {
      "reason_code": "tool_not_authorized",
      "tool": "...",
      "capability": "..."
    }
  }
}
```

---

## Configuration

The proxy is configured via a TOML file (`--config <path>`):

```toml
[downstream]
command = "a2g-echo-mcp-server"   # downstream MCP server binary
args = []

mandate_path   = "/tmp/mandate.cbor"
gateway_socket = "/tmp/a2g-gateway.sock"
demo_key_file  = "/tmp/a2g-gateway-demo-keys.json"

[trust_anchor]
mode = "self_sovereign"   # or "roots" with pubkeys = ["<hex>", ...]

[tool_map]
echo = "vehicle.climate.set_temperature"
# Unmapped tools → pay.unknown (always-HITL, fail-closed)
```

### Tool mapping

| MCP tool name | A2G capability | Default verdict |
|---------------|----------------|-----------------|
| `echo` | `vehicle.climate.set_temperature` | ALLOW (if in mandate, vehicle parked) |
| (any unmapped) | `pay.unknown` | ESCALATE (always-HITL) |

---

## MCP error codes

| Code | Constant | Meaning |
|------|----------|---------|
| `-32001` | `ERR_A2G_DENIED` | `decide()` returned DENY or EXPIRED |
| `-32002` | `ERR_A2G_ESCALATE` | `decide()` returned PENDING_APPROVAL (HITL needed) |
| `-32003` | `ERR_A2G_GATEWAY` | Gateway refused after core ALLOW |
| `-32004` | `ERR_A2G_INTERNAL` | Proxy internal error (mandate load, key error, etc.) |

---

## Trust notes (rich-domain)

The proxy runs in the **rich domain** — the same trust tier as the CLI.
It can be compromised.  The Enforcing Gateway remains the sole enforcement point:

- The gateway independently verifies every receipt signature (Step 2).
- The gateway re-checks forbidden domains (Step 1 / Step 1.5).
- The gateway verifies freshness, nonce, and action hash (Steps 4–6).
- A compromised proxy key that doesn't match the gateway's receipt verifying key
  will fail gateway Step 2 regardless.

See ADR-0019 and ADR-0010 for the full threat model.

---

## Running the e2e tests

```bash
cargo test -p a2g-mcp-proxy --test e2e -- --nocapture
```

Tests cover:
- (a) Allowed call passes with receipt metadata in `_meta`.
- (b) Denied call: downstream receives zero calls.
- (c) Unmapped tool: downstream receives zero calls.
- (d) `pay.*` tool without binding: ESCALATE, downstream not called.
- (e) Missing gateway socket: `GovernanceContext::load` fails gracefully.
