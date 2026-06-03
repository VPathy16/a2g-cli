# ADR-0004: Pure Decision Path (`decide()`)

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `refactor/decide-purepath`

---

## Context

`enforce()` in a2g-core previously read the wall clock internally (`Utc::now()`) for TTL and jurisdiction checks, making it impossible to:

1. Test time-sensitive policy rules (TTL boundaries, operating hours) deterministically.
2. Move the decision core toward `no_std` — `Utc::now()` requires OS system-call access.
3. Profile the pure CPU cost of enforcement without OS call noise.

## Decision

### 1. `decide<L: EnforceLedger>()` — pure decision function

```rust
pub fn decide<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
    now: DateTime<Utc>,
) -> Result<Verdict, Box<dyn std::error::Error>>
```

- **No wall-clock reads.** `now` is caller-supplied.
- **No filesystem I/O.** Path checks use `canonicalize_path_logical()` (pure normalisation; no `std::fs::canonicalize`).
- **No ledger writes.** `is_revoked` and `count_recent` are read-only ledger queries.
- Runs all 8 enforcement steps (input validation → revocation → signature → TTL → tool+boundary → jurisdiction → escalation → rate-limit). Step 8 (authority chain) is performed by the CLI wrapper after `decide()` returns.
- Generic over `L: EnforceLedger` (static dispatch, zero vtable overhead).

### 2. `enforce<L: EnforceLedger>()` — thin public wrapper

```rust
pub fn enforce<L: EnforceLedger>(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &L,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    decide(mandate_str, tool, params, ledger, Utc::now())
}
```

Same external behaviour as the previous `enforce()`. The only observable change is the generic parameter `<L: EnforceLedger>` replacing `&dyn EnforceLedger` — a **compile-time-only** change with no runtime effect for existing callers (concrete types inferred; no cast needed).

### 3. Clock injection via `mandate::verify_signature()`

`verify_mandate()` previously called `Utc::now()` internally for TTL. A new `verify_signature()` function performs the ed25519 check only. `decide()` calls `verify_signature()` (Step 1) and then performs the TTL comparison against the injected `now` (Step 2). `verify_mandate()` is unchanged and still used by the `a2g verify` CLI command.

### 4. Static dispatch

Changed `&dyn EnforceLedger` → `<L: EnforceLedger>` on `enforce()` and `decide()`. This is an **API shape change**: callers that stored a `&dyn EnforceLedger` need to use a concrete type or an explicit `impl Trait` bound. All existing callers in the CLI pass a concrete `SqliteLedger`, so no call site changes were required. This change is called out explicitly per the task constraints.

### 5. `no_std` scaffolding

Added `[features] default = ["std"] std = []` to `a2g-core/Cargo.toml`. The `canonicalize_path()` function (filesystem-aware) is gated under `#[cfg(feature = "std")]`. The `decide()` path uses only `canonicalize_path_logical()`. See `docs/no_std-blockers.md` for remaining blockers.

## Consequences

### Positive

- TTL and jurisdiction tests are now deterministic — no wall-clock flakiness.
- `decide()` can be called from any context that can supply a `DateTime<Utc>`.
- Static dispatch eliminates one level of indirection on the hot path.
- Criterion benchmark isolates pure CPU cost of the decision pipeline.

### Neutral

- `enforce()` is one function call deeper. Inlined by the compiler in release builds.
- `verify_signature()` added to `mandate.rs` public API — additive change.

### Negative / Blockers

- Full `no_std` is not possible yet; see `docs/no_std-blockers.md`.
- `Box<dyn std::error::Error>` return type on `decide()` still requires `std`. Replacing with a custom error enum is future work.

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Inject `now` as `u64` Unix timestamp | `DateTime<Utc>` is already in scope; avoids conversion bugs |
| Keep `&dyn EnforceLedger` (dynamic dispatch) | Per task spec: static dispatch requested |
| Wrap `decide()` result in a new type | No behaviour change needed; thin wrapper is sufficient |
| Thread-local clock mock | Non-deterministic in async contexts; explicit parameter is cleaner |
