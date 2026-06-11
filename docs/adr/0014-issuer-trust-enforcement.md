# ADR-0014 — Issuer Trust Enforcement

**Status**: Accepted  
**Date**: 2026-06-11  
**Context**: a2g-core `enforce.rs`, a2g-ffi ABI

---

## Context

Prior to this ADR, `decide_core()` accepted any mandate that was internally
self-consistent — the signature verified against the embedded `issuer_pubkey`
and `issuer_did` matched `did:a2g:<bs58(pubkey)>`, but no check was made that
the issuer is a party the host process has chosen to trust. Any party in
possession of an ed25519 key pair could mint a valid mandate and have it
accepted.

This is the **issuer-trust gap**: the library enforced cryptographic integrity
(the mandate was signed by whoever holds the key) but not cryptographic trust
(that key is an authority the operator recognises).

---

## Decision

### 1. `TrustAnchor<'a>` enum (a2g-core)

A new `TrustAnchor<'a>` enum is added to `a2g_core::enforce`:

```rust
pub enum TrustAnchor<'a> {
    SelfSovereign,
    Roots(&'a [[u8; 32]]),
    Chain {
        trusted_roots: &'a [[u8; 32]],
        chain: &'a [AuthorityLink],
    },
}
```

`SelfSovereign` is an explicit, named opt-in — not the absence of a choice.
Callers must pass a `TrustAnchor` to every decision function. There is no
default that silently accepts untrusted issuers.

### 2. Fail-explicit default

Passing `NULL` (C ABI) or omitting the `trust` parameter is not possible — the
Rust API requires `&TrustAnchor<'_>` as a mandatory parameter; the C ABI
requires a non-NULL `A2gTrustAnchorHandle *`. `NULL` returns
`A2G_DECISION_ERROR` immediately — there is no implicit default trust mode
(see §4 below for the C ABI).

### 3. Step 1.5 in `decide_core()`

`check_issuer_trust()` is called at **Step 1.5**, after Step 1 (signature /
self-consistency check) and before Step 2 (TTL check):

```
forbidden pre-check
  → Step 0: revocation check
  → Step 1: signature / self-consistency
  → Step 1.5: issuer trust enforcement  ← NEW
  → Step 2: TTL
  → Steps 3–7: capability / state / rate-limit / ...
```

**Ordering rationale**: the forbidden-domain pre-check runs first and
unconditionally — it must fire even for untrusted mandates so that
Forbidden-domain tools are never executed regardless of trust configuration.
The issuer-trust check is placed after the sig check (Step 1) because verifying
the public key in the mandate is a prerequisite for matching it against trust
roots; checking issuer trust before signature verification would be
meaningless.

A failed `check_issuer_trust` produces `Decision::Deny` with
`policy_rule = "issuer_untrusted: <error>"`. It is a returned error, never a
panic (conformant with `#23` panic-freedom lints).

### 4. C ABI: `A2gTrustAnchorHandle`

A new opaque handle type is added to the C ABI:

```c
typedef struct A2gTrustAnchorHandle A2gTrustAnchorHandle;
```

Constructors:

| Function | Mode |
|---|---|
| `a2g_trust_anchor_self_sovereign()` | `SelfSovereign` — explicit opt-in for testing |
| `a2g_trust_anchor_roots(pubkeys_flat, count)` | `Roots` — one or more trusted issuer pubkeys |

Destructor: `a2g_trust_anchor_free(handle)`. NULL is a no-op.

`a2g_decide` and `a2g_decide_with_approval` both gain a mandatory
`const A2gTrustAnchorHandle *trust` parameter. Passing `NULL` returns
`A2G_DECISION_ERROR` immediately — there is no implicit default trust mode.

**The FFI owns no keys.** The `A2gTrustAnchorHandle` holds the host-supplied
public key bytes. No private keys cross the ABI (unchanged from ADR-0009 §Key
exclusion rationale).

### 5. `SelfSovereign` is a deliberate token, not the absence of a choice

The name "SelfSovereign" communicates unambiguously: "this process is
asserting it trusts the mandate it built itself; it has waived external issuer
verification." This is a valid, greppable, auditable choice — not a trap.
Production deployments should use `Roots` or `Chain`.

---

## Consequences

- **Breaking API change** — `decide()`, `enforce()`, `decide_with_approval()`
  gain a mandatory `trust: &TrustAnchor<'_>` parameter. All call sites updated.
- **Breaking ABI change** — `a2g_decide()` and `a2g_decide_with_approval()`
  gain a mandatory `trust` parameter. C integrators must update call sites and
  create a trust anchor handle. Old binaries will not link against the new
  shared library.
- `a2g-core` remains `rusqlite`-free and `no_std`-scaffolded; `TrustAnchor`
  holds only borrowed slices (no heap allocation at the core level).
- Three conformance vectors added: `09-issuer-trust/it-001` through `it-003`.
- The existing `test_mandate()` helper in `enforce.rs` tests uses
  `SelfSovereign` explicitly; this makes the self-sovereign opt-in visible in
  every test that exercises it.

---

## Alternatives considered

**Implicit self-sovereign default** — rejected. Silent acceptance of untrusted
issuers is the gap this ADR closes. Any default that silently accepts would
recreate it.

**`Option<TrustAnchor>`** with `None = SelfSovereign` — rejected. `None`
communicates "not configured" rather than "I have deliberately chosen
self-sovereign." Using an explicit variant makes the choice greppable and
auditable.

**Key pinning at mandate parse time** — considered, but `parse_and_verify_cbor`
is called deep in `decide_core` after the forbidden pre-check. Threading an
anchor through the parse layer would couple trust enforcement to the parsing
step and make the step ordering harder to audit. Keeping `check_issuer_trust`
at Step 1.5 makes the ordering explicit and close to where the other
pre-execution steps live.
