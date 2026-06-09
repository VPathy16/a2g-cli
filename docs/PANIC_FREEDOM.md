# Panic Freedom — a2g-core

## Policy

The `decide()` function and every function on its call path **must not panic or abort on any input**. Failures must return `Err(…)` so callers can resolve them to a fail-safe DENY verdict. This policy is enforced at compile time via crate-level Clippy lints and verified at runtime via property tests.

## Enforced Lints (`crates/a2g-core/src/lib.rs`)

```rust
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::unreachable,
    clippy::todo,
    clippy::panicking_unwrap
)]
```

These lints are crate-wide. Test modules use `#[allow(...)]` locally to permit `unwrap` in test-only code, which is not on the decision path.

## Fail-Safe DENY Contract

Any `Err` returned by `decide()` is treated as a **DENY verdict** by the caller — never as a crash.

At the FFI boundary (`a2g-ffi`), `make_error_verdict()` converts `Err` to `A2G_DECISION_ERROR`, which maps to `A2G_DECISION_DENY` (value `0`). The safe degraded state is: **deny the action**.

This contract means:

- A corrupted mandate → `Err` → DENY (not a crash)
- A NaN or infinite speed value → `Ok(Verdict { decision: Deny })` (not a crash)
- A 100 000-character tool name → `Ok(Deny)` or `Err` → DENY (not a crash)
- A poisoned Mutex → recovered via `unwrap_or_else(|e| e.into_inner())` (not a crash)

The contract does **not** alter any currently-correct verdict. It only governs previously-panicking edge cases; all 72 conformance vectors continue to pass with identical results.

## Replacement Patterns Applied

| Panic pattern | Panic-free replacement |
|---|---|
| `slice[i]` | `slice.get(i).ok_or(…)?` or `.windows(2)` / slice patterns |
| `a + b` (integer) | `a.saturating_add(b)` |
| `a - b` (integer) | `a.saturating_sub(b)` |
| `-n` (integer) | `n.saturating_neg()` |
| `n as i64` (truncating cast) | `i64::try_from(n).unwrap_or(i64::MAX)` |
| `now + Duration` (DateTime) | `now.checked_add_signed(Duration).unwrap_or(now)` |
| `(dt1 - dt2).num_seconds()` | `dt1.signed_duration_since(dt2).num_seconds()` |
| `.lock().unwrap()` (Mutex) | `.lock().unwrap_or_else(\|e\| e.into_inner())` |
| `.take().unwrap()` (Option) | `.take().ok_or("…")?` |
| `vec[0]` | `.first().ok_or("…")?` |
| `score += n` (u32 counter) | `score = score.saturating_add(n)` |

## Property Tests (`crates/a2g-core/tests/panic_freedom.rs`)

Six proptest properties (512 cases each) verify the panic-freedom contract:

| Test | Input | Invariant |
|---|---|---|
| `prop_arbitrary_mandate_string_never_panics` | Any string as mandate | Returns `Ok` or `Err` — never panics |
| `prop_extreme_speed_never_panics` | Any `f64` (NaN, ±∞, subnormal) as speed | Returns verdict or `Err` — never panics |
| `prop_arbitrary_tool_name_never_panics` | Any string as tool name | Returns `Ok` or `Err` — never panics |
| `prop_arbitrary_params_never_panics` | Any string values for path/url/command | Returns `Ok` or `Err` — never panics |
| `prop_forbidden_tools_always_deny` | Valid mandate permitting safety-critical tools | Always returns DENY or `Err` |
| `prop_valid_mandate_allowed_tool_returns_allow` | Valid signed mandate with permitted tool | Always returns ALLOW |

Six deterministic edge-case regression tests round out the suite:

- Empty mandate string → `Err`
- Null bytes in mandate → `Err`
- NaN speed → `Ok(Deny)`
- Infinite speed → `Ok(Deny)`
- 100 000-character tool name → no panic
- `make_error_verdict()` contract verified end-to-end

Run with:

```sh
cargo test -p a2g-core --test panic_freedom
```

## Honest Residuals

The following scenarios remain outside the compile-time guarantee and are documented here for transparency:

1. **Allocation failure (`OOM`).** Rust `alloc` panics on OOM by default (no `try_alloc` in stable `std`). This is standard Rust behaviour and cannot be addressed without a custom allocator. A safety-island deployment should provision memory conservatively.

2. **Stack overflow.** Deep recursion or very large stack frames can cause an OS-level stack overflow signal. The decision path is not recursive, so this risk is low in practice.

3. **`no_std` blockers.** `a2g-core` retains the `no_std` scaffold (`default = ["std"]`), but several dependencies (`serde_json`, `chrono`, `regex`) require `std`. The full path to bare-metal `no_std` is tracked in `docs/no_std-blockers.md`.

4. **Thread-level panics from other crates.** Only `a2g-core`'s own code is covered by these lints. If a dependency panics, the lints cannot prevent it. Dependencies were reviewed for obvious panic sites; none were found on the hot decision path.

## ISO 26262 / ASIL Context

This module is architected for use as a safety island between an AI agent and vehicle APIs. The panic-freedom policy supports ASIL-B objectives by ensuring the governance engine remains available and provides safe output (DENY) even when faced with malformed or adversarial inputs. Formal ASIL certification would require a certified toolchain (e.g. Ferrocene/`rustc`) and a full FMEA; that work is out of scope for this implementation.
