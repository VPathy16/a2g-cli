# ADR-0009 — FFI / C-ABI Layer

**Status**: Accepted  
**Date**: 2026-06-04  
**Context**: a2g-core, a2g-ffi crate

---

## Context

a2g-core's enforcement engine must be embeddable in host processes written in C, C++, Android NDK, Rust, and other languages. The engine is pure Rust with no I/O; it is ready for embedding, but there is no stable binary interface. This ADR defines the C ABI exposed by the `a2g-ffi` crate.

---

## Decision

### Crate: `a2g-ffi`

A new `crates/a2g-ffi` crate is added with `crate-type = ["cdylib", "staticlib"]`. It depends on `a2g-core` and has no database dependency. `a2g-core` remains `rusqlite`-free.

### Decision enum: `A2gDecision` (`#[repr(i32)]`)

| Variant           | C constant                     | Value |
|-------------------|--------------------------------|-------|
| `Allow`           | `A2G_DECISION_ALLOW`           | 0     |
| `Deny`            | `A2G_DECISION_DENY`            | 1     |
| `Expired`         | `A2G_DECISION_EXPIRED`         | 2     |
| `PendingApproval` | `A2G_DECISION_PENDING_APPROVAL`| 3     |
| `Error`           | `A2G_DECISION_ERROR`           | -1    |

**`ESCALATE` is intentionally absent.** The post-#12 decision model uses `PendingApproval`; the FFI ABI is aligned with that.

The variant values are **ABI-stable** and must not be reordered. Additions must always be appended.

### Opaque handles

Two opaque struct types are exposed as forward-declared pointers:

- `A2gVerdictHandle` — holds a `Verdict` plus cached `CString` accessors. Obtained from `a2g_decide` or `a2g_decide_with_approval`. Freed with `a2g_verdict_free`.
- `A2gVerifiedStateHandle` — wraps an operator-trusted `VerifiedVehicleState`. Obtained from `a2g_verified_state_operator_trusted`. Freed with `a2g_verified_state_free`.

The Rust structs are not `#[repr(C)]`; C sees only forward declarations. The host process never dereferences them.

### Phase 1: `a2g_decide`

```c
A2gDecision a2g_decide(
    const char *mandate_toml,
    const char *tool,
    const char *params_json,
    const A2gVerifiedStateHandle *state,  /* NULL → fail-safe */
    A2gVerdictHandle **out_verdict
);
```

Runs the full 8-step enforcement pipeline. No I/O; no blocking. `*out_verdict` is always written; never NULL on return.

On `A2G_DECISION_PENDING_APPROVAL`, the binding JSON is available via `a2g_verdict_binding_json`. Pass this to Phase 2 together with the grant.

### Phase 2: `a2g_decide_with_approval`

```c
A2gDecision a2g_decide_with_approval(
    const char *mandate_toml,
    const char *tool,
    const char *params_json,
    const A2gVerifiedStateHandle *state,
    const char *binding_json,  /* JSON of PendingApprovalBinding from Phase 1 */
    const char *grant_json,    /* JSON of ApprovalGrant from human approver */
    A2gVerdictHandle **out_verdict
);
```

Validates the grant and runs Phase 2 enforcement. The `binding_json` must be exactly what was returned by `a2g_verdict_binding_json` in Phase 1; re-computing it at Phase 2 time would break hash matching across the async gap (see ADR-0008).

### Key exclusion rationale

No private keys, signing operations, or cryptographic secrets cross the ABI. Attestation verification (`AttestedVehicleState::verify`) is host-side by design. The ABI does not expose:

- `AttestedVehicleState` or its `verify()` method
- Any signing key parameters
- The `a2g_core::identity` key-generation functions

The only state-creation function is `a2g_verified_state_operator_trusted` (explicitly interim, named "operator_trusted"). This communicates to the caller that they are asserting trust, not proving it cryptographically. Refer to ADR-0007 §4.

### Verified state handle contract

`a2g_verified_state_operator_trusted` sets `trust_basis = StateTrust::OperatorTrusted`. The resulting `state_trust` field on the verdict is "operator_trusted". Auditors can distinguish this from "attested" decisions.

The host must not reuse a state handle across multiple decisions if vehicle state may have changed between calls. Each decision should use a freshly constructed handle.

### Buffer ownership

- `A2gVerdictHandle` and `A2gVerifiedStateHandle` pointers are Rust-heap-allocated; free with `a2g_verdict_free` / `a2g_verified_state_free`.
- Strings returned by accessor functions (`a2g_verdict_id`, `a2g_verdict_policy_rule`, etc.) are owned by the handle. They are valid until the handle is freed. **Do not call `free()` on them.**
- `a2g_test_mandate_toml()` returns a separately heap-allocated `char*` that must be freed with `a2g_string_free`.
- Passing NULL to any free function is always safe (no-op).

### Panic safety

All `extern "C"` functions that call into `a2g-core` wrap the call in `std::panic::catch_unwind`. A panic results in `A2G_DECISION_ERROR` and a valid (but empty) error verdict handle. The host process is never brought down by a Rust panic.

### Header generation

`cbindgen` generates `crates/a2g-ffi/include/a2g.h`. CI runs a drift check (`cbindgen --verify`) to ensure the committed header matches the source. Do not edit the header manually.

### ABI stability promise

Once this crate reaches version 1.0:
- Existing variant values will not change.
- Existing function signatures will not change.
- New functions may be added without a breaking bump.
- Removals require a major version bump.

At v0.x, minor version bumps may include breaking changes.

---

## Consequences

- Any language with C FFI can embed the A2G enforcement engine.
- The host retains attestation logic; a2g-ffi stays I/O-free.
- `a2g-core` remains no_std-scaffolded and rusqlite-free.
- `a2g-ffi` is `std`-enabled (needed for `catch_unwind` and `CString`).
- The C smoke test (`tests/smoke_test.c`) is compiled and run in CI to detect ABI regressions.
- Cross-compilation to `aarch64-unknown-linux-gnu` is checked in CI (build-only).

---

## Open questions

- **Async approval notification**: The current ABI requires the host to poll or use its own notification mechanism for Phase 2. A future `a2g_wait_for_approval` or callback API may be added.
- **Batch decisions**: Currently one decision per call. A batch API for high-throughput embedded use cases may be added in a future minor version.
