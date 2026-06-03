# ADR-0004: Pure Decision Path (`decide()`)

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `refactor/decide-purepath`  
**Amended:** 2026-06-03 — added symlink-mitigation section  

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
- **No filesystem I/O.** Path checks use `canonicalize_path_logical()` (pure normalisation; no `std::fs::canonicalize`). When called through `enforce()`, the path has already been resolved before `decide()` runs.
- **No ledger writes.** `is_revoked` and `count_recent` are read-only ledger queries.
- Runs all 8 enforcement steps (input validation → revocation → signature → TTL → tool+boundary → jurisdiction → escalation → rate-limit). Step 8 (authority chain) is performed by the CLI wrapper after `decide()` returns.
- Generic over `L: EnforceLedger` (static dispatch, zero vtable overhead).

### 2. `enforce<L: EnforceLedger>()` — I/O boundary and public wrapper

`enforce()` is the only place in a2g-core that performs I/O. It:

1. **Resolves the `path` parameter** (if present) via `std::fs::canonicalize` before calling `decide()`. This is the symlink-escape mitigation — see §Symlink mitigation below.
2. **Injects the current wall-clock time** (`Utc::now()`) and delegates to `decide()`.

Same external behaviour as the previous `enforce()`. The only observable change vs. the pre-refactor version is the generic parameter `<L: EnforceLedger>` replacing `&dyn EnforceLedger` — a **compile-time-only** change with no runtime effect for existing callers.

### 3. Symlink mitigation — attack class and accepted residuals

#### Attack class: symlink-based boundary escape / confused-deputy

Without path resolution, an agent can plant a symlink inside an allowed boundary
pointing to a target outside it:

```
workspace/evil_link → /etc/passwd        # symlinked file
workspace/outsidedir/ → /etc/            # symlinked parent directory
```

`decide()` operates on the *lexical* path string. `workspace/evil_link` passes
`glob_matches("workspace/**", ...)` — ALLOW. The OS follows the symlink and the
agent reads `/etc/passwd`. The allowed boundary was a confused deputy.

#### Mitigation in `enforce()`

`enforce()` calls `resolve_path_for_enforce()` before `decide()`. This function:

1. Logical-normalises the raw path (collapse `.`, `..`) — no I/O, ensures the leaf is never `..`.
2. Calls `std::fs::canonicalize` on the normalised path. If the path exists, its real absolute path is returned (all symlinks resolved, including intermediate directory symlinks).
3. If the path does not exist (first-time file creation): resolves the parent directory and re-appends the leaf component. The parent must be a real directory; a symlinked parent is resolved to its real location. After step 1, the leaf is guaranteed not to be `..`, so re-attaching it is safe.
4. If neither the path nor its parent can be resolved: returns `Err`. `enforce()` propagates the error. No unresolved path is passed to `decide()`.

`decide()` then receives the resolved absolute path. A symlink target outside the workspace fails the `workspace/**` glob check → DENY.

#### Non-existent-path policy (deliberate choice)

For writes to files that do not yet exist: the parent directory is canonicalised and the leaf filename is re-attached. This allows legitimate first-time file creation in a real workspace directory. If the parent directory is itself a symlink pointing outside the workspace, it resolves to the real (out-of-boundary) location → the resolved path fails the boundary check → DENY.

Edge case defended: the leaf component after logical normalisation is never `..` (step 1 collapses all `..` before the split). A leaf that is a *dangling* symlink (the symlink exists but its target does not) is treated as a plain filename — the symlink name is inside the workspace, and the non-existent target cannot be accessed. This is part of the accepted TOCTOU residual.

#### Accepted residual limitations

These limitations are **accepted** — they are not regressions and cannot be addressed at the policy-evaluation layer without changes to the execution architecture.

**TOCTOU (Time-Of-Check/Time-Of-Use):** Path resolution occurs at decision time (`enforce()` call). The executor performs the actual operation later, under a separate kernel call. An attacker who can plant a symlink *between* the `enforce()` call and the executor's `open()` call escapes this check. Mitigation: minimise the gap between decision and execution; use `O_NOFOLLOW` or similar in the executor.

**Executor-mismatch:** A2G decides; a separate process (LangChain, CrewAI, MCP server, etc.) executes. Both must resolve paths identically — same working directory, same mount namespace, same libc behaviour. If the executor uses a different CWD or operates inside a container with different mounts, the resolution at decision time is not bound at use time.

#### Boundary of this guarantee

`fs_read`, `fs_write`, and `fs_deny` are **path-string policy checks, not OS-level confinement.** The symlink mitigation in `enforce()` raises the bar for the *static* case (symlinks planted before the `enforce()` call), but it does not provide OS-level isolation. Real confinement requires the agent runtime to run inside a sandbox (Linux namespaces, seccomp, container, or similar) that independently enforces the same filesystem boundaries at the kernel level.

### 4. Clock injection via `mandate::verify_signature()`

`verify_mandate()` previously called `Utc::now()` internally for TTL. A new `verify_signature()` function performs the ed25519 check only. `decide()` calls `verify_signature()` (Step 1) and then performs the TTL comparison against the injected `now` (Step 2). `verify_mandate()` is unchanged and still used by the `a2g verify` CLI command.

### 5. Static dispatch

Changed `&dyn EnforceLedger` → `<L: EnforceLedger>` on `enforce()` and `decide()`. This is an **API shape change**: callers that stored a `&dyn EnforceLedger` need to use a concrete type or an explicit `impl Trait` bound. All existing callers in the CLI pass a concrete `SqliteLedger`, so no call site changes were required. This change is called out explicitly per the task constraints.

### 6. `no_std` scaffolding

Added `[features] default = ["std"] std = []` to `a2g-core/Cargo.toml`. The `canonicalize_path()` and `resolve_path_for_enforce()` functions (filesystem-aware) are gated under `#[cfg(feature = "std")]`. The `decide()` path uses only `canonicalize_path_logical()`. See `docs/no_std-blockers.md` for remaining blockers.

## Consequences

### Positive

- TTL and jurisdiction tests are now deterministic — no wall-clock flakiness.
- `decide()` can be called from any context that can supply a `DateTime<Utc>`.
- Static dispatch eliminates one level of indirection on the hot path.
- Criterion benchmark isolates pure CPU cost of the decision pipeline.
- The static symlink-escape is now DENY at the `enforce()` layer; confirmed by unit tests and battle tests.

### Neutral

- `enforce()` now does two I/O operations (one `canonicalize` call + `Utc::now()`). Both are fast syscalls on the hot path.
- `verify_signature()` added to `mandate.rs` public API — additive change.
- Unit tests for workspace boundary logic (`test_workspace_root_*`) now call `decide()` directly rather than `enforce()`, since they use synthetic paths that don't exist on disk. This is correct — those tests exercise policy evaluation, not symlink resolution.

### Negative / Blockers

- Full `no_std` is not possible yet; see `docs/no_std-blockers.md`.
- `Box<dyn std::error::Error>` return type on `decide()` still requires `std`. Replacing with a custom error enum is future work.
- TOCTOU and executor-mismatch residuals are documented above and accepted.

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Inject `now` as `u64` Unix timestamp | `DateTime<Utc>` is already in scope; avoids conversion bugs |
| Keep `&dyn EnforceLedger` (dynamic dispatch) | Per task spec: static dispatch requested |
| Wrap `decide()` result in a new type | No behaviour change needed; thin wrapper is sufficient |
| Thread-local clock mock | Non-deterministic in async contexts; explicit parameter is cleaner |
| Resolve paths in the CLI layer only | Would leave library consumers of `enforce()` unprotected; mitigation belongs at the I/O boundary of the core wrapper |
| Resolve paths inside `decide()` | Violates purity guarantee; blocks `no_std` path |
| `O_NOFOLLOW` at open time | Requires executor cooperation; out of scope for the policy engine |
