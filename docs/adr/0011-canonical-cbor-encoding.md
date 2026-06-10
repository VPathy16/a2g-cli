# ADR-0011: Canonical CBOR Encoding for Signed Payloads

**Status:** Accepted  
**Date:** 2026-06-10  
**Supersedes:** none  
**See also:** ADR-0008 (HITL), ADR-0009 (FFI), ADR-0010 (Gateway)

---

## Context

Before this change, three signed wire-format payloads used colon-delimited ASCII strings:

| Payload | Old format |
|---------|-----------|
| Gateway receipt | `RECEIPT:{verdict_id}:{decision}:{tool}:{request_hash}:{binding_id}:{issued_at_ms}:{nonce_hex}` |
| Pending-approval binding (gateway + FFI) | `BINDING:{binding_id}:{request_hash}:{escalate_to}:{ttl_unix_secs}` |
| Approval grant | `APPROVAL:{binding_id}:{request_hash}:{expires_at}` (signed over SHA-256 of the string) |

String concatenation with colons has two known vulnerabilities:

1. **Delimiter injection**: A field value containing `:` shifts subsequent field positions, making it possible to forge a different logical payload that produces the same byte sequence.  
   Example: `BINDING:a:b:c:d` cannot be distinguished from `BINDING:a:b`:` c:d` if the parser is not strict about field counts.
2. **Ambiguous serialization**: RFC 3339 timestamps and UUIDs are stable, but any field accepting free-form text (e.g., `escalate_to`, `tool`) could smuggle colons.

Additionally, the approval grant was signed over `SHA-256(APPROVAL:...)` rather than directly over the payload bytes. The pre-hash step is unnecessary: ed25519 applies its own internal 512-bit hash (SHA-512). The double-hash added complexity without improving security.

**Mandate payload** (`MANDATE:...` from §4.5) is explicitly **out of scope** for this ADR. It has no delimiter-injection risk because its fields are tab-separated and include a length-prefixed body. Mandate→CBOR migration is a separate task.

---

## Decision

Replace the three colon-delimited signed payloads with **canonical deterministic CBOR** (RFC 8949) using the `minicbor` crate.

### Encoding rules

All payloads use **CBOR array encoding** (`#[cbor(array)]` in minicbor derive):

- Field order equals struct declaration order (positional, by `#[n(idx)]`).
- No key-sorting is needed because arrays have no keys.
- Integer fields use shortest-form (canonical) CBOR integer encoding.
- Byte-string fields (`request_hash`, `nonce`) are encoded as CBOR `bstr` (major type 2) via `minicbor::bytes::ByteVec`, not as integer arrays.
- String fields are encoded as CBOR `tstr` (major type 3).

### Payload structures

**BindingPayload** (gateway and FFI):
```
["BINDING", binding_id, request_hash(bstr 32B), escalate_to, ttl_unix_secs(int)]
```

**GrantPayload** (HITL approval):
```
["APPROVAL", binding_id, request_hash(bstr 32B), expires_at(tstr RFC3339)]
```

**ReceiptPayload** (gateway receipt):
```
["RECEIPT", verdict_id, decision, tool, request_hash(bstr 32B), binding_id, issued_at_ms(int), nonce(bstr 16B)]
```

### Signing change for grants

`ApprovalGrant::payload_bytes()` now returns the raw CBOR bytes directly. The signing call `signing_key.sign(&payload_bytes)` passes the CBOR bytes to ed25519, which applies its internal SHA-512. The previous `SHA-256(APPROVAL:...)` pre-hash is removed.

### What is NOT changed

- `compute_request_hash()` — `REQUEST:...` SHA-256 used as a field value inside payloads (not itself signed).
- `receipt.rs` chain hash — SHA-256 of colon-delimited string for tamper-evident audit chain (not ed25519-signed).
- Mandate signing payload — explicitly out of scope; see §4.5.

---

## Consequences

### Breaking

Old colon-delimited receipts, bindings, and grants will **not** verify against the new code. There is no dual-accept fallback. All parties must upgrade atomically.

### Benefits

- Eliminates delimiter-injection as an attack surface.
- Binary fields (`request_hash`, `nonce`) are encoded as proper bytes, not hex strings within strings — both smaller and unambiguous.
- The single `encode_canonical()` helper (`a2g_core::cbor`) is the only encoding entry point for all three payload types; no future divergence possible.
- Removes the unnecessary SHA-256 pre-hash from grant signing.

### no_std compatibility

`minicbor` supports `no_std` with `default-features = false, features = ["derive", "alloc"]`. The current workspace enables `features = ["derive", "alloc"]` which is std-compatible. To enable no_std for a2g-core, the `alloc` feature is all that is needed from minicbor's side. Current no_std blockers are in `docs/no_std-blockers.md` and are unrelated to CBOR.

### Test coverage

- `crates/a2g-core/tests/cbor_canonical.rs` — determinism, round-trip, malformed-CBOR panic-freedom, and proptest property tests.
- Conformance vectors `gc-008` and `gc-009` — malformed-hex rejection at the gateway step 2.
- All existing unit, integration, and e2e tests continue to pass.
