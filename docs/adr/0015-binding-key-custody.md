# ADR-0015 — Binding-Key Custody Migration into the Gateway

**Status**: Accepted  
**Date**: 2026-06-11  
**Context**: a2g-ffi, a2g-gateway, a2g-core (hitl)  
**Closes**: SPEC Appendix A.1; ADR-0009 §"interim binding key"; ADR-0010 §Key Ownership (implementation)

---

## Context

ADR-0009 introduced a per-process ephemeral ed25519 key (`OnceLock<SigningKey>`
in `a2g-ffi`) to MAC-protect the Phase-2 `PendingApprovalBinding` JSON across
the C ABI. That key lived in the **rich domain** — the same process that
requests the action held the key that authenticates the binding. ADR-0010
specified that the binding-signing key must move into the Enforcing Gateway,
and the gateway's `SignBinding` operation was implemented, but the FFI layer
still carried its own in-process signer as a parallel "DEMO ONLY" path.
SPEC §11.1 called this a circular trust assumption; SPEC §10.1 makes gateway
key ownership a Level 2 conformance requirement.

This ADR removes the parallel path. There is **one** binding signer in the
system: the gateway.

## Decision

### One shared wire type: `a2g_core::hitl::SignedBinding`

The signed-binding blob `{ binding fields…, a2g_mac }` previously existed as
two private structs (`a2g-ffi::SignedBinding`, `a2g-gateway::SignedBindingWire`).
It is now a single public type in `a2g-core::hitl`:

```rust
pub struct SignedBinding {
    #[serde(flatten)]
    pub binding: PendingApprovalBinding,
    pub a2g_mac: String, // hex ed25519 over canonical CBOR BindingPayload (ADR-0011)
}

impl SignedBinding {
    pub fn payload_bytes(&PendingApprovalBinding) -> Result<Vec<u8>, A2gError>;
    pub fn sign(&PendingApprovalBinding, &SigningKey) -> Result<Self, A2gError>;   // gateway only
    pub fn verify(&self, &VerifyingKey) -> Result<PendingApprovalBinding, A2gError>;
    pub fn verify_json(&str, &VerifyingKey) -> Result<PendingApprovalBinding, A2gError>;
}
```

`sign()` living in a2g-core does not move key custody — custody is about who
*holds* the `SigningKey`, and only the gateway constructs one for bindings.

### Rich domain holds the verifying key only

- The `OnceLock<SigningKey>` and all binding-signing code are **removed** from
  `a2g-ffi`. `grep -r "OnceLock" crates/a2g-ffi` returns nothing.
- `a2g_decide()` Phase 1 returns the **unsigned** `PendingApprovalBinding` JSON
  via `a2g_verdict_binding_json()`. The host forwards it to the gateway's
  `SignBinding` request and receives the signed blob.
- `a2g_decide_with_approval()` gains a mandatory parameter:

```c
A2gDecision a2g_decide_with_approval(
    const uint8_t *mandate_cbor, uintptr_t mandate_cbor_len,
    const char *tool, const char *params_json,
    const A2gVerifiedStateHandle *state,
    const char *signed_binding_json,   /* gateway-signed blob */
    const uint8_t *binding_pubkey,     /* 32-byte gateway binding verifying key; NULL → ERROR */
    const char *grant_json,
    const A2gTrustAnchorHandle *trust,
    A2gVerdictHandle **out_verdict);
```

Passing NULL for `binding_pubkey` returns `A2G_DECISION_ERROR` immediately —
fail-explicit, the same contract as ADR-0014's trust anchor. There is no
in-process fallback key.

### Gateway key distribution

- `DemoKeys` and the `GetPublicKeys` response gain `binding_verifying_key_hex`,
  so the rich domain can bootstrap the verifying key in the dev tier. In
  production the key is provisioned out-of-band.

### Production startup check (SPEC §10.1 Level 3)

`a2g-gateway --production` requires `--keystore <path>` pointing at a
provisioned keystore JSON:

```json
{
  "binding_signing_key_hex": "…32-byte seed…",
  "receipt_verifying_key_hex": "…",
  "attester_verifying_key_hex": "…",
  "operator_verifying_key_hex": "…"
}
```

Missing flag, unreadable file, malformed JSON, or invalid key material →
the gateway logs a fatal reason and exits non-zero. Dev mode (default)
generates ephemeral keys with a loud warning, unchanged.

The keystore contains the gateway's **private** binding key and only
**public** keys for the other parties — the receipt, attester, and operator
signing keys belong to other trust domains and never enter the gateway's
address space.

## Security properties

| Threat | Defense |
|---|---|
| Rich domain mints its own binding (forge) | Gateway queue is populated only by `SignBinding`; an unknown `binding_id` is refused at verification step 7. Phase 2 in the FFI refuses any blob not signed by the gateway key. |
| TTL extension / field substitution between Phase 1 and Phase 2 | ed25519 over canonical CBOR `BindingPayload`; any field change invalidates the signature. |
| Replay of a binding into a different process | Unlike the per-process `OnceLock` key, the gateway signature is portable by design — replay is prevented by the queue's one-use consume semantics (step 7), not by key locality. |
| Production deployment with ephemeral keys | `--production` refuses to start without a provisioned keystore. |

## Consequences

- **Breaking C ABI change**: `a2g_decide_with_approval` has a new mandatory
  parameter and new `binding_json` semantics. Old binaries will not link.
- The FFI's Phase-2 path now requires a gateway (or an out-of-band signer that
  holds the binding key) — single-process HITL without a gateway is no longer
  possible. This is intentional: it was the circular trust assumption.
- `a2g-core` gains no new dependencies (ed25519-dalek, serde, serde_json were
  already present).
- The two private struct definitions are gone; gateway and FFI cannot drift.

## Alternatives considered

- **Keep the FFI key as an optional fallback** — rejected: dual-accept paths on
  an authentication boundary are exactly what this codebase forbids for wire
  formats; the same logic applies to key custody.
- **Pass the verifying key once via a global setter** (`a2g_set_binding_key`) —
  rejected: process-global mutable state complicates the thread-safety story;
  a per-call parameter is explicit and matches the trust-anchor pattern.
