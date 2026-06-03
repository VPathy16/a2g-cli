# ADR 0001: Cargo Workspace Split — a2g-core / a2g-cli

**Status:** Accepted  
**Date:** 2026-06-03  
**Deciders:** a2g maintainers

---

## Context

The original `a2g-cli` crate was a single Cargo package that mixed:

1. **Domain logic** — mandate parsing, enforcement pipeline, receipt generation, identity/DID
   operations, authority delegation, and governance output formatting.
2. **Infrastructure** — SQLite-backed ledger (`rusqlite`), CLI argument parsing (`clap`), and
   human-readable terminal output.

As downstream consumers (test harnesses, language bindings, CI tools) needed to import the
enforcement engine without pulling in SQLite and a CLI framework, the monolith became an obstacle.
`rusqlite` with the `bundled` feature links a statically-compiled SQLite, adding ~1 MB to every
binary that imports the crate — even if no database is ever opened.

## Decision

Split the single crate into a Cargo workspace with two members:

| Crate | Path | Role |
|---|---|---|
| `a2g-core` | `crates/a2g-core` | Pure-Rust library; no SQLite, no CLI |
| `a2g` (binary) | `crates/a2g-cli` | Thin CLI layer; owns SQLite ledger |

### What moved into `a2g-core`

- `identity.rs` — DID generation and key management
- `mandate.rs` — TOML parsing, hash computation, signature verification
- `enforce.rs` — 8-step enforcement pipeline, `Verdict` type
- `receipt.rs` — receipt generation and chain initialization
- `authority.rs` — delegation tree and authority log
- `proposal.rs` — proposal scoring and risk model
- `output_gov.rs` — machine-readable governance output formatting
- `ledger.rs` — **trait only** (`EnforceLedger` with `is_revoked` + `count_recent`)

### What stayed in `a2g-cli`

- `ledger.rs` — concrete `Ledger` struct backed by SQLite (`rusqlite`)
- `main.rs` — `clap`-based CLI with all commands and flags
- `lineage.rs`, `trust_summary.rs`, `test_harness.rs`, `visual_receipt.rs` — CLI-specific display
  and testing utilities

### Trait abstraction for the ledger boundary

`enforce::enforce()` previously took `&crate::ledger::Ledger` (the concrete SQLite struct).
After the split it takes `&dyn EnforceLedger`:

```rust
// crates/a2g-core/src/ledger.rs
pub trait EnforceLedger {
    fn is_revoked(&self, agent_did: &str, mandate_hash: &str)
        -> Result<bool, Box<dyn std::error::Error>>;
    fn count_recent(&self, agent_did: &str, seconds: i64)
        -> Result<u64, Box<dyn std::error::Error>>;
}
```

Only these two methods are used inside the enforcement pipeline. All other ledger operations
(query, log authority events, bulk export) are called directly on the concrete `Ledger` from
`main.rs` and are not part of the trait.

Unit tests inside `a2g-core` use a zero-dependency `TestLedger` no-op that always returns
`is_revoked = false` and `count_recent = 0`, keeping the crate free of SQLite even in test builds.

### Dependency invariant

`cargo tree -p a2g-core | grep rusqlite` must return no output. This is enforced by:

- `a2g-core/Cargo.toml` has no `rusqlite` entry.
- The `EnforceLedger` trait uses only `std` error types.
- No `#[cfg(test)]` block in `a2g-core` imports `rusqlite`.

## Consequences

**Positive**

- Downstream crates can depend on `a2g-core` to embed the enforcement engine with a ~30 KB
  dependency footprint instead of ~1 MB.
- `cargo build -p a2g-core` compiles cleanly with zero native dependencies.
- All 39 existing unit tests continue to pass unchanged in meaning; only import paths were updated
  where necessary.
- `cargo clippy --all-targets -- -D warnings` is clean across the entire workspace.

**Negative / Trade-offs**

- One additional `Cargo.toml` and crate boundary to maintain.
- Dynamic dispatch (`&dyn EnforceLedger`) in the hot path of `enforce()`. The enforcement
  function is called at most once per tool invocation, so the vtable overhead is negligible.

**Neutral**

- The enforcement pipeline logic (8 steps, signature schemes, domain-separation prefixes, mandate
  TOML format, receipt format, ledger schema) is **unchanged**. This ADR records a structural
  refactor only.
- CLI behaviour — all commands, flags, `--output json` — is preserved exactly.
