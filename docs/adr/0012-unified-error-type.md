# ADR-0012 — Unified Error Type (`A2gError`)

**Status:** Accepted  
**Date:** 2026-06-10  
**Deciders:** core team

---

## Context

Prior to this ADR, `a2g-core`'s public API had no consistent error type:

- Most fallible functions returned `Result<T, Box<dyn std::error::Error>>`.
- Some returned `Result<T, &'static str>` or `Result<T, String>`.
- Two ad-hoc enums existed in the same crate: `ApprovalGrantError` (in `hitl.rs`) and `AttestationError` (in `vehicle.rs`).

This prevented `a2g-core` from targeting `no_std` environments (Blocker #1 in `docs/no_std-blockers.md`) because `std::error::Error` is a std-only trait and `Box<dyn Trait>` requires the std allocator.

It also made the public API fragile: callers had to down-cast boxed errors or lose the error variant information entirely.

---

## Decision

Introduce a single crate-local error enum `A2gError` in `crates/a2g-core/src/error.rs` and migrate every fallible public function in `a2g-core` to return `Result<_, A2gError>`.

### `A2gError` variants

| Variant | Replaces |
|---------|----------|
| `MandateParse(String)` | `toml::de::Error` boxed |
| `Json(String)` | `serde_json::Error` boxed |
| `HexDecode(String)` | `hex::FromHexError` boxed |
| `SignatureInvalid` | `ApprovalGrantError::InvalidSignature`, `ed25519_dalek::SignatureError` boxed |
| `InvalidKey` | `ApprovalGrantError::InvalidPubkey`, `AttestationError::InvalidKey`, boxed key errors |
| `CborEncode` | `minicbor::encode::Error` (unit: not inspectable by callers) |
| `CborDecode` | `minicbor::decode::Error` (unit) |
| `MandateExpired` | `"mandate expired"` string |
| `MandateInvalid(String)` | Various `Box<dyn Error>` / String errors in mandate validation |
| `GrantExpired` | `ApprovalGrantError::Expired` |
| `BindingMismatch { field: &'static str }` | `ApprovalGrantError::BindingMismatch` |
| `AuthorityChain(String)` | authority-hierarchy validation errors |
| `InvalidSpeed(String)` | speed boundary validation |
| `AttestationBadSignature` | `AttestationError::BadSignature` |
| `AttestationInvalidKey` | `AttestationError::InvalidKey` |
| `AttestationStaleNonce` | `AttestationError::StaleNonce` |
| `AttestationStale` | `AttestationError::Stale` |
| `PathError(String)` | path-resolve errors in `enforce.rs` |
| `LedgerError(String)` | external ledger implementation errors |
| `Internal(String)` | catch-all for internal invariant violations |

### Trait bounds

- `core::fmt::Display` — always available (no_std).
- `core::fmt::Debug` — derived.
- `std::error::Error` — implemented under `#[cfg(feature = "std")]` only, with no additional methods (the default blanket impl suffices).

The enum is marked `#[non_exhaustive]` so that adding variants in the future is not a breaking change for downstream match arms.

### Removed types

- `hitl::ApprovalGrantError` — eliminated; variants absorbed into `A2gError`.
- `vehicle::AttestationError` — eliminated; variants absorbed into `A2gError`.

### External call sites

| Crate | Change |
|-------|--------|
| `a2g-cli/src/ledger.rs` | `EnforceLedger` impl maps SQLite errors → `A2gError::LedgerError` |
| `a2g-gateway/src/protocol.rs` | `canonical_bytes()` returns `Result<Vec<u8>, a2g_core::A2gError>` |
| `a2g-gateway/src/server.rs` | `binding_bytes()` returns `Result<Vec<u8>, a2g_core::A2gError>` |
| `a2g-ffi/src/lib.rs` | `NoopLedger` returns `A2gError`; `binding_bytes()` maps `A2gError` to `None` |
| `a2g-conformance` | `NoopLedger` returns `A2gError` |
| `a2g-core/tests/panic_freedom.rs` | `NoopLedger` returns `A2gError` |

---

## Consequences

### Positive

- **no_std Blocker #1 resolved.** `a2g-core` no longer requires `std::error::Error` on the decision path.
- **Single inspectable error type.** Callers can match on `A2gError` variants; the old boxed approach required lossy `to_string()` comparisons.
- **Fail-safe DENY contract preserved.** Any `A2gError` on the decision path still resolves to DENY at the enforcement boundary; the variant carries diagnostic information but does not change the verdict.
- **Panic-freedom lints remain satisfied.** No new `.unwrap()` or `.expect()` calls were introduced in `a2g-core`.
- **138 unit tests and 58 conformance vectors unchanged.**

### Negative / Trade-offs

- **Downstream `impl EnforceLedger` must update.** Any crate implementing the `EnforceLedger` trait must now return `A2gError` instead of `Box<dyn Error>`. The migration path is `.map_err(|e| A2gError::LedgerError(e.to_string()))`.
- **`ApprovalGrantError` and `AttestationError` are breaking removals.** Callers matching on those types must be updated. No compatibility shim is provided.
- **No `From<X>` impls.** Conversions from external error types are intentionally explicit (`.map_err(...)`) to keep the error origin visible and avoid invisible coercions.

---

## References

- `docs/no_std-blockers.md` — Blocker #1 marked resolved
- `crates/a2g-core/src/error.rs` — implementation
- ADR-0004 (pure decision path), ADR-0011 (canonical CBOR encoding)
