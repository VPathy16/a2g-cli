# A2G C/C++ Integration Guide

This document is the hand-off reference for platform engineers integrating the
`a2g-ffi` static library into ECU firmware, infotainment middleware, or any
other C/C++ software stack.

Audience: engineers with an AUTOSAR, AAOS-VHAL, or embedded-Linux middleware
background who need to understand the trust model, ABI contract, and build
integration before writing production code.

---

## Contents

1. [Three-Zone Architecture](#1-three-zone-architecture)
2. [Capability Domains](#2-capability-domains)
3. [C ABI Reference](#3-c-abi-reference)
4. [Build and Cross-Compile](#4-build-and-cross-compile)
5. [Integration Sequence](#5-integration-sequence)
6. [Phase 1 → Phase 2 (Human-in-the-Loop)](#6-phase-1--phase-2-human-in-the-loop)
7. [Performance Model](#7-performance-model)
8. [Safety Posture](#8-safety-posture)
9. [Known Limitations and Roadmap](#9-known-limitations-and-roadmap)

---

## 1. Three-Zone Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Zone 1 — Untrusted Infotainment Domain                                  │
│                                                                          │
│   ┌────────────────────────────┐                                         │
│   │  AI Agent (LLM)            │  tool_call(name, params, mandate_toml)  │
│   │  Infotainment App          │ ──────────────────────────────────────► │
│   └────────────────────────────┘                                         │
│                                                                          │
│   No direct HAL access.  All tool calls are requests, not commands.      │
└───────────────────────────────────────────────┬──────────────────────────┘
                                                │
              ╔═════════════════════════════════╪══════════════════════╗
              ║  Trust Boundary                                        ║
              ║  · Ed25519 mandate signature verified against issuer   ║
              ║    DID before any policy evaluation begins             ║
              ║  · Inbound vehicle state attestation checked           ║
              ║  · Forged or absent mandate → hard DENY, no exception  ║
              ╚═════════════════════════════════╪══════════════════════╝
                                                │
┌───────────────────────────────────────────────▼──────────────────────────┐
│  Zone 2 — Secure Gateway                                                 │
│                                                                          │
│   ┌──────────────────────────────────────────────────────────────────┐   │
│   │  decide()                                                        │   │
│   │  · Pure deterministic function — no I/O, no wall-clock reads    │   │
│   │  · All external inputs (time, state) injected explicitly         │   │
│   │  · Returns ALLOW / DENY / PENDING_APPROVAL / EXPIRED             │   │
│   └──────────────────────────┬───────────────────────────────────────┘   │
│                              │ ALLOW                                     │
│   ┌──────────────────────────▼───────────────────────────────────────┐   │
│   │  Enforcing Writer                                                │   │
│   │  · Sole process with HAL write permissions                       │   │
│   │  · Independently re-verifies the ALLOW receipt before acting    │   │
│   │  · No ALLOW receipt → no HAL write, ever                        │   │
│   └──────────────────────────┬───────────────────────────────────────┘   │
│                              │ signed receipt appended                   │
│   ┌──────────────────────────▼───────────────────────────────────────┐   │
│   │  Signed Receipt Ledger                                           │   │
│   │  · Hash-chained append-only log (genesis hash = 0×64)           │   │
│   │  · Each receipt carries SHA-256(prev_receipt ‖ payload)         │   │
│   │  · Tamper evidence: any gap or reorder breaks the chain         │   │
│   └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ALLOW verdict ────────── signed receipt ──────────────────────────────► │
└───────────────────────────────────────────────┬──────────────────────────┘
                                                │ signed receipt required
┌───────────────────────────────────────────────▼──────────────────────────┐
│  Zone 3 — Vehicle Hardware Actuators                                     │
│  (HVAC module · window controller · media subsystem · CAN frame writer)  │
│                                                                          │
│  Hardware actions only execute when the Enforcing Writer presents a      │
│  valid signed receipt.  The infotainment domain has no path to this      │
│  layer that bypasses Zone 2.                                             │
└──────────────────────────────────────────────────────────────────────────┘
```

### Key properties

| Property | Guarantee |
|---|---|
| Inbound signature check | Every tool call is rejected unless the mandate carries a valid Ed25519 signature from the issuer DID |
| decide() purity | No side effects, no I/O, no blocking — safe to call from any scheduling context |
| Sole HAL writer | The Enforcing Writer is the only process with HAL write access; the infotainment domain has no direct path |
| Receipt chain | Every ALLOW verdict is written to the ledger before any hardware action; gaps in the chain are detectable |
| PENDING_APPROVAL MAC | The Phase 1 binding token is MAC-protected with a per-process ephemeral Ed25519 key; tampering causes Phase 2 to return ERROR |

---

## 2. Capability Domains

The policy engine classifies every tool call into one of four domains before
evaluating mandate content.  Domain classification overrides mandate permissions
for Forbidden tools.

| Domain | Examples | Default decision |
|---|---|---|
| **Comfort** | `read_file`, `write_file`, `list_directory` | ALLOW (if in mandate tools) |
| **Convenience** | `vehicle.climate.set_temperature`, `vehicle.media.play` | ALLOW (if in mandate tools) |
| **Sensitive** | `WINDOW_POS`, `DOOR_LOCK`, `SEAT_POS` | PENDING_APPROVAL (if in `escalate_tools`) or ALLOW with verified state |
| **Forbidden** | `delete_all_data`, `format_storage`, `disable_ecu` | Hard DENY — no mandate can override |

Mandate capabilities are an allow-list: any tool not explicitly listed under
`[capabilities].tools` is denied even if it is not in the Forbidden domain.

---

## 3. C ABI Reference

### Headers

| Header | Purpose |
|---|---|
| `crates/a2g-ffi/include/a2g.h` | Generated by cbindgen — all type and function declarations |
| `crates/a2g-ffi/include/a2g_integration.h` | Wrapper — includes `a2g.h` and adds ABI stability, thread-safety, and ownership documentation |

Include `a2g_integration.h` in your integration code.

### Decision codes

```c
A2G_DECISION_ALLOW             =  0   // Proceed; forward receipt to Enforcing Writer
A2G_DECISION_DENY              =  1   // Refuse; do not execute the tool
A2G_DECISION_EXPIRED           =  2   // Mandate TTL elapsed; reject and request renewal
A2G_DECISION_PENDING_APPROVAL  =  3   // Phase 1 complete; await human grant (Phase 2)
A2G_DECISION_ERROR             = -1   // Invalid input, internal error, or tampered MAC
```

These values are ABI-stable — do not reorder (ADR-0009 §ABI stability).

### Handle types

Both handles are **opaque** — never dereference or embed by value.

| Handle | Allocator | Free with |
|---|---|---|
| `A2gVerdictHandle *` | `a2g_decide()` / `a2g_decide_with_approval()` | `a2g_verdict_free()` |
| `A2gVerifiedStateHandle *` | `a2g_verified_state_operator_trusted()` | `a2g_verified_state_free()` |

String pointers returned by `a2g_verdict_id()`, `a2g_verdict_tool()`, etc. are
valid until `a2g_verdict_free()` is called on the owning handle.  Do not call
`free()` on them separately.

Strings returned by `a2g_test_mandate_toml()` are heap-allocated and must be
freed with `a2g_string_free()` — not `free()`.

### Thread safety

- Concurrent calls on **different** handles are safe.
- Do not share a single handle across threads without external synchronisation.
- `a2g_verified_state_operator_trusted()` is thread-safe.
- The per-process binding-integrity key is initialized once (OnceLock) and
  is read-only thereafter — no additional synchronisation required.

---

## 4. Build and Cross-Compile

### Prerequisites

- Rust stable toolchain (`rustup toolchain install stable`)
- `cbindgen` 0.27 (only needed if regenerating the header):
  `cargo install cbindgen --version 0.27.0 --locked`

### Build the Rust library

```sh
# Host build (produces liba2g_ffi.a and liba2g_ffi.so)
cargo build -p a2g-ffi --release

# Static archive is at:
#   target/release/liba2g_ffi.a
```

### no_std architecture split

The codebase is split across two trust levels:

| Crate | std requirement | Notes |
|---|---|---|
| `a2g-core` | no_std-scaffolded (blockers exist — see below) | Policy engine, mandate verification, HITL logic |
| `a2g-ffi` | std | ABI shim, panic catch, handle allocation |
| `a2g-gateway` | std | Enforcing Writer, SQLite ledger, CLI |

`a2g-core` is the boundary-crossing crate.  It is deliberately kept free of
`rusqlite` and heavy I/O dependencies.  The current no_std blockers (tracked in
`docs/no_std-blockers.md`) are:

- `Box<dyn std::error::Error>` in public APIs (high severity)
- `toml` crate for mandate parsing (high severity — no `alloc` port)
- `regex`, `uuid::new_v4()`, `std::sync::Mutex` (medium severity)

Once these are resolved, `a2g-core` can be built for bare-metal targets
(e.g., Cortex-M with a custom allocator) while `a2g-ffi` and `a2g-gateway`
continue to require std.

### Cross-compile to aarch64 (Linux, ECU target)

```sh
# Install the target and cross toolchain once
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install -y gcc-aarch64-linux-gnu

# Build the FFI crate for aarch64
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    cargo build -p a2g-ffi --target aarch64-unknown-linux-gnu --release

# Static archive is at:
#   target/aarch64-unknown-linux-gnu/release/liba2g_ffi.a
```

### Link your C program

```sh
# Host
cc -I crates/a2g-ffi/include \
   your_integration.c \
   -L target/release -la2g_ffi \
   -lpthread -ldl -lm \
   -o your_binary

# aarch64 cross
aarch64-linux-gnu-gcc -I crates/a2g-ffi/include \
   your_integration.c \
   -L target/aarch64-unknown-linux-gnu/release -la2g_ffi \
   -lpthread -ldl -lm \
   -o your_binary_aarch64
```

Alternatively, use the provided Makefile in `examples/c_integration/`:

```sh
make -C examples/c_integration \
     A2G_LIB_DIR=$(pwd)/target/release \
     A2G_INCLUDE=$(pwd)/crates/a2g-ffi/include
./examples/c_integration/a2g_integration
```

### C++ integration

The header is `extern "C"` compatible.  In a C++ source file:

```cpp
extern "C" {
#include "a2g_integration.h"
}
```

No C++ wrapper classes are provided; the opaque-handle pattern maps cleanly to
RAII wrappers if desired.

---

## 5. Integration Sequence

The following sequence shows a complete tool-call evaluation cycle from the
infotainment domain down to a hardware actuator.

```
Infotainment Agent         Trust Boundary        Secure Gateway          HAL
       │                        │                      │                   │
       │  tool_call(            │                      │                   │
       │    "WINDOW_POS",       │                      │                   │
       │    params,             │                      │                   │
       │    mandate_toml)       │                      │                   │
       │───────────────────────►│                      │                   │
       │                        │ verify Ed25519 sig   │                   │
       │                        │ check mandate TTL    │                   │
       │                        │──────────────────────►                   │
       │                        │                      │ a2g_decide()      │
       │                        │                      │ (pure fn, no I/O) │
       │                        │                      │                   │
       │           ◄────────────────────────────────── │ ALLOW verdict +   │
       │           verdict + receipt                   │ signed receipt    │
       │                        │                      │                   │
       │                        │                      │ write receipt     │
       │                        │                      │ to ledger         │
       │                        │                      │──────────────────►│
       │                        │                      │  HAL write        │
       │                        │                      │  (e.g. CAN frame) │
```

### Startup sequence

```c
/* 1. Load or receive the mandate TOML from your trust root. */
const char *mandate_toml = load_mandate_from_secure_store();

/* 2. (Optional) Create an operator-trusted vehicle state.
 *    In production, this comes from a cryptographically attested state feed.
 *    The operator-trusted constructor is the interim path for integrations
 *    that have not yet wired up full attestation (ADR-0009 §State trust). */
A2gVerifiedStateHandle *state =
    a2g_verified_state_operator_trusted(speed_kph, gear, actor);

/* 3. For each tool call from the agent: */
A2gVerdictHandle *verdict = NULL;
A2gDecision d = a2g_decide(mandate_toml, tool, params_json, state, &verdict);

switch (d) {
case A2G_DECISION_ALLOW:
    forward_to_enforcing_writer(a2g_verdict_id(verdict));
    break;
case A2G_DECISION_DENY:
case A2G_DECISION_EXPIRED:
    log_denial(a2g_verdict_policy_rule(verdict));
    break;
case A2G_DECISION_PENDING_APPROVAL:
    enqueue_approval_request(a2g_verdict_binding_json(verdict));
    break;
default:
    log_error(a2g_verdict_policy_rule(verdict));
    break;
}

a2g_verdict_free(verdict);

/* 4. Shutdown */
a2g_verified_state_free(state);
```

See `examples/c_integration/main.c` for a compilable demonstration.

---

## 6. Phase 1 → Phase 2 (Human-in-the-Loop)

Some tools require explicit human approval before execution.  This is
configured per-mandate by listing the tool in both `[capabilities].tools` and
`[escalation].escalate_tools`.

### Phase 1 — requesting approval

```c
A2gVerdictHandle *h1 = NULL;
A2gDecision d1 = a2g_decide(mandate, tool, params, state, &h1);

if (d1 == A2G_DECISION_PENDING_APPROVAL) {
    /*
     * binding_json is MAC-protected with a per-process ephemeral Ed25519 key.
     * Any field modification invalidates the MAC and causes Phase 2 to return
     * A2G_DECISION_ERROR.  Pass it unmodified to Phase 2.
     */
    const char *binding_json = a2g_verdict_binding_json(h1);
    const char *binding_id   = a2g_verdict_binding_id(h1);
    const char *request_hash = a2g_verdict_request_hash(h1);

    /* Forward to approval backend.  The binding TTL is 5 minutes. */
    approval_backend_request(binding_id, request_hash,
                             escalate_to_did,   /* from binding JSON */
                             binding_json);      /* stored for Phase 2 */
}

a2g_verdict_free(h1);
```

### Phase 2 — consuming the approval grant

When the human approver grants approval, your backend produces a signed
`ApprovalGrant` JSON and returns it to the gateway.

```c
/*
 * grant_json is produced by the approver backend and looks like:
 * {
 *   "binding_id":       "<UUID from Phase 1>",
 *   "request_hash":     "<hex from Phase 1>",
 *   "approver_did":     "did:a2g:operator-console",
 *   "approver_pubkey":  "<hex ed25519 public key>",
 *   "signature":        "<hex ed25519 signature>",
 *   "expires_at":       "<RFC3339>",
 *   "parent_receipt_hash": "<hex Phase 1 receipt hash>"
 * }
 *
 * The signature covers SHA-256("APPROVAL:<binding_id>:<request_hash>:<expires_at>").
 * Domain separation ("APPROVAL:" prefix) prevents replay across contexts.
 */

A2gVerdictHandle *h2 = NULL;
A2gDecision d2 = a2g_decide_with_approval(
    mandate, tool, params, state,
    binding_json,   /* unmodified from Phase 1 */
    grant_json,     /* from approver backend */
    &h2);

if (d2 == A2G_DECISION_ALLOW) {
    forward_to_enforcing_writer(a2g_verdict_id(h2));
}

a2g_verdict_free(h2);
```

### Replay prevention

- `request_hash` covers the mandate hash, tool name, params hash, and Phase 1
  timestamp.  An approval for action A cannot be replayed to authorise action B.
- The pending binding TTL is 5 minutes; grants also carry an `expires_at`.
- A tampered `binding_json` field causes Phase 2 to return `A2G_DECISION_ERROR`
  before the grant is even examined.

---

## 7. Performance Model

`a2g_decide()` is a **pure, deterministic function with a bounded worst-case
execution time (WCET)**:

- **Zero I/O** in the decision path.  No file reads, no network calls, no
  database queries.  All external inputs (current time, vehicle state) are
  injected by the caller.
- **No LLM in the decision path.**  The policy engine is a rule-based evaluator
  over a static mandate structure.  There is no generative inference, no model
  loading, and no probabilistic output.
- **Deterministic**.  Given identical inputs, `decide()` always returns the same
  decision.  There is no randomness, no lazy initialisation, and no
  shared mutable state accessed during evaluation.
- **No allocation in the hot path** (mandate is pre-parsed at the call boundary;
  the verdict is a single stack-allocated struct written to the heap once).

This profile makes `decide()` suitable for integration into real-time scheduling
contexts where call-site latency must be bounded and auditable.

Actual WCET depends on mandate complexity (number of tools, pattern matching
over path/network deny lists) and the target platform.  Measure on your target
hardware under worst-case mandate complexity before setting scheduling budgets.

---

## 8. Safety Posture

`a2g-core` is **architected for ASIL-B** with a path to Ferrocene-qualified
Rust.  It is **not certified** at this time.

| Dimension | Current state |
|---|---|
| Language | Rust stable; Ferrocene-qualified Rust is a drop-in replacement for the `a2g-core` crate once no_std blockers are resolved |
| Memory safety | Rust ownership model eliminates buffer overflows, use-after-free, and data races at the language level |
| `a2g-core` external deps | Deliberately minimal; `rusqlite` is excluded from `a2g-core` (enforced by CI) |
| Panic handling | All `a2g-ffi` entry points wrap with `panic::catch_unwind`; a panic returns `A2G_DECISION_ERROR` rather than aborting the process |
| ABI isolation | Private Rust types do not cross the ABI boundary; opaque handles prevent the C caller from observing or modifying internal state |
| Ledger integrity | Hash-chained receipt log; any tampered or missing receipt breaks the chain and is detectable at audit time |
| HITL binding integrity | Phase 1 binding is MAC-protected with a per-process ephemeral key (OnceLock); the C host cannot forge or replay a Phase 1 token |

### No private keys cross the ABI boundary (ADR-0009 §Key exclusion)

The mandate issuer's Ed25519 signing key never crosses the FFI boundary.
`a2g-ffi` only consumes the signed mandate TOML for verification; it does not
expose key material.

### Ferrocene path

Once the no_std blockers in `a2g-core` are resolved, the crate can be compiled
with the Ferrocene qualified-Rust toolchain and its `libcore` replacement.
`a2g-ffi` and `a2g-gateway` will continue to use std and are not on the
Ferrocene path.  The safety boundary is drawn at the `a2g-core` crate.

---

## 9. Known Limitations and Roadmap

| Limitation | Tracking |
|---|---|
| `a2g-core` no_std blockers (8 items) | `docs/no_std-blockers.md` |
| `a2g_verified_state_operator_trusted` is interim — full cryptographic state attestation is host-side and not yet exposed via ABI | ADR-0009 §State trust |
| Ledger persistence uses SQLite (in `a2g-gateway`); `a2g-core` itself is SQLite-free | `docs/no_std-blockers.md` |
| Phase 2 ApprovalGrant signing is host-side; no signing helper is exported via the C ABI | ADR-0008 |

---

## Reference

- `SPEC.md` — protocol specification including mandate format (§4), capability
  domains (§5), and the two-phase HITL contract (§6)
- `CONFORMANCE.md` — conformance test suite status (54 vectors, 0 known divergences)
- `docs/no_std-blockers.md` — current blockers for `a2g-core` no_std port
- `crates/a2g-ffi/include/a2g.h` — generated C header (cbindgen)
- `crates/a2g-ffi/include/a2g_integration.h` — wrapper header with full contract docs
- `examples/c_integration/` — minimal buildable C integration example
- `crates/a2g-ffi/tests/smoke_test.c` — CI smoke test (ALLOW, DENY, state trust, error paths)
