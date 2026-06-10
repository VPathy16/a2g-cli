# no_std Blockers for a2g-core

This document enumerates all blockers to a complete `no_std` build of `a2g-core`.  
**Do not attempt a no_std build until these are resolved** (see ADR-0004).

The feature flag `default = ["std"]` is in place. Disabling it (`--no-default-features`) will produce compile errors at each blocker below.

---

## Blockers

### ~~1. `Box<dyn std::error::Error>`~~ — **RESOLVED (ADR-0012)**

| | |
|--|--|
| **Location** | ~~Return type of `decide()`, `enforce()`, and virtually every fallible function in the crate~~ |
| **Resolution** | `A2gError` enum added in `crates/a2g-core/src/error.rs`. All public API functions in a2g-core now return `Result<_, A2gError>`. `core::fmt::Display` is the only bound; `std::error::Error` is gated behind `#[cfg(feature = "std")]`. `ApprovalGrantError` and `AttestationError` ad-hoc enums removed. See ADR-0012. |

### 2. `toml` crate

| | |
|--|--|
| **Location** | `mandate.rs` — `toml::from_str`, `toml::to_string_pretty` |
| **Reason** | The `toml` crate (v0.8) has no `no_std` support; it depends on `std::collections::HashMap` and `std::io` |
| **Candidate replacement** | `toml_edit` (also std-only at time of writing). Long-term: a `serde`-compatible TOML library that targets `alloc`-only, or switch mandate format to CBOR/MessagePack (`minicbor`, `postcard`). |

### 3. `regex` crate

| | |
|--|--|
| **Location** | `output_gov.rs` — `RegexBuilder::new(...).size_limit(...).build()` |
| **Reason** | `regex` requires `std` (uses `HashMap` for the DFA cache, `Box<dyn Error>` for build errors) |
| **Candidate replacement** | `regex-lite` (std-only but smaller); `aho-corasick` for literal patterns; hand-rolled pattern matching for the small set of output-governance rules. |

### 4. `uuid::Uuid::new_v4()` — OsRng

| | |
|--|--|
| **Location** | `enforce.rs` — `Uuid::new_v4()` in `decide()` for `correlation_id` |
| **Reason** | `Uuid::new_v4()` uses `getrandom` which calls OS entropy. In no_std environments there is no OS. |
| **Candidate replacement** | Accept `correlation_id: Option<&str>` as a parameter to `decide()`, letting callers supply a pre-generated ID. Fall back to a counter-based ID in no_std. |

### 5. `std::sync::Mutex` — `PREV_HASH` receipt chain

| | |
|--|--|
| **Location** | `receipt.rs` — `static PREV_HASH: Mutex<String>` |
| **Reason** | `std::sync::Mutex` is std-only. The global receipt chain requires shared mutable state. |
| **Candidate replacement** | Move receipt chaining out of the core crate entirely (into the CLI layer, which is always std). `decide()` can return the hash inputs; the caller chains them. |

### 6. `chrono::Utc::now()` — system time (in `enforce()` wrapper)

| | |
|--|--|
| **Location** | `enforce.rs` — `enforce()` calls `Utc::now()` before delegating to `decide()` |
| **Reason** | `Utc::now()` uses `std::time::SystemTime`. **Already removed from `decide()`.** The wrapper `enforce()` still needs it, but `decide()` is clean. |
| **Candidate replacement** | `enforce()` is a convenience function for std callers. In no_std, callers use `decide()` directly and supply `now`. No change needed for `decide()`. |

### 7. `serde_json` — partial `alloc` support

| | |
|--|--|
| **Location** | `enforce.rs` — `serde_json::to_string(params)`, `serde_json::Value` |
| **Reason** | `serde_json` supports `alloc`-only mode (`no_std` + global allocator) via `std = false` feature, but `serde_json::Value` internally uses `std::collections::BTreeMap`. This may work in practice with `alloc`. |
| **Candidate replacement** | Enable `serde_json`'s `alloc` feature flag; audit whether `Value` works in alloc-only. Lower-risk alternative: `serde-json-core` for fixed-buffer JSON parsing. |

### Note: `vehicle` module (ADR-0005) — no new blockers

`crates/a2g-core/src/vehicle.rs` is no_std-compatible on the decision path:
- `classify_vehicle_tool()` and `evaluate_vehicle_state()` are pure with no heap allocation on the Allow path.
- `StateVerdict::Deny` carries `&'static str` (no heap).
- `extract_vehicle_state()` uses `serde_json` — already covered by Blocker 7 above.

### 8. `ed25519-dalek` — getrandom dependency

| | |
|--|--|
| **Location** | `mandate.rs` — signature operations |
| **Reason** | `ed25519-dalek` with `rand_core` feature pulls in `getrandom`, which needs OS entropy for key generation. Verification only (no key generation) would work in no_std. |
| **Candidate replacement** | For a no_std verify-only path, use `ed25519-dalek` without `rand_core`. Key generation stays in the CLI (std) layer. |

---

## Summary Table

| Blocker | Severity | Scope | Effort to Fix |
|---------|----------|-------|---------------|
| ~~`Box<dyn std::error::Error>`~~ | ~~**High**~~ | ~~Entire public API~~ | **RESOLVED — ADR-0012** |
| `toml` crate | **High** | Mandate parsing | Large — format change or new library |
| `regex` crate | **Medium** | Output governance only | Medium — hand-rolled or `aho-corasick` |
| `uuid` OsRng | **Medium** | `decide()` correlation ID | Small — make it a parameter |
| `std::sync::Mutex` (receipt) | **Medium** | Receipt chaining | Medium — move to CLI layer |
| `Utc::now()` in `enforce()` | **Low** | `enforce()` wrapper only | Already resolved in `decide()` |
| `serde_json` (alloc) | **Low** | Params hashing | Small — feature flag |
| `ed25519-dalek` (rand_core) | **Low** | Key gen only | Small — split gen vs verify |

The path of least resistance for a partial no_std build:
1. ~~Blocker 1 resolved (ADR-0012).~~
2. Resolve blockers 4, 6, 7, 8 (small effort).
3. Gate `enforce()` under `#[cfg(feature = "std")]`.
4. Move receipt chaining to the CLI (blocker 5).
5. Replace `regex` with `aho-corasick` (blocker 3).
6. Blocker 2 (`toml`) requires a format change and is out of scope until the protocol stabilises.
