# A2G Protocol Conformance

This document covers the A2G conformance test suite: how to run it, how to consume the vectors as an external implementation, what each conformance level requires, how to claim conformance, and the known divergences between the reference implementation and [SPEC.md](SPEC.md).

---

## Running the Suite

```bash
# From the workspace root
cargo run -p a2g-conformance
```

The runner loads every `conformance/vectors/**/*.json` vector, exercises the reference implementation, and prints a per-vector verdict: `PASS`, `KNOWN_FAIL`, or `FAIL`.

Exit code `0` — all non-known-failing vectors passed.
Exit code `1` — one or more unexpected failures detected.

Override the vectors directory:

```bash
A2G_VECTORS_DIR=/path/to/my/vectors cargo run -p a2g-conformance
```

---

## Vector Format

Each vector is a self-contained JSON object with three top-level sections:

```json
{
  "id":          "vs-001",
  "spec_ref":    "§2.2",
  "category":    "verdict-semantics",
  "description": "Comfort capability with valid mandate produces ALLOW",
  "known_failing": false,
  "known_failing_reason": null,
  "input": { ... },
  "expected": { ... }
}
```

### `input` fields

| Field | Type | Meaning |
|---|---|---|
| `mandate_capabilities` | `string[]` | Tools to include in `capabilities.tools` |
| `mandate_escalate_tools` | `string[]` | Tools to include in `escalation.escalate_tools` |
| `mandate_expires_in_hours` | `int` | Mandate TTL passed to the signer (negative = sign with TTL 0, effectively already expired) |
| `mandate_bad_signature` | `bool` | Tamper the signature bytes after signing |
| `mandate_use_spec_signing` | `bool` | Sign with SPEC §4.5 canonical payload instead of implementation payload (see Known Divergences) |
| `mandate_workspace_root` | `string\|null` | `mandate.workspace_root` field |
| `mandate_operating_hours` | `string\|null` | `jurisdiction.operating_hours` (e.g. `"02:00-03:00"`) |
| `mandate_rate_limit` | `int` | `limits.max_calls_per_minute` |
| `mandate_fs_deny/read/write` | `string[]` | `boundaries.fs_deny/read/write` |
| `capability` | `string` | Tool name passed to `decide()` |
| `params` | `object` | Params object passed to `decide()` |
| `state_speed_kph` | `float\|null` | Vehicle speed; `null` = omit state (fail-safe triggers for Sensitive tools) |
| `state_gear` | `string\|null` | `Park` \| `Drive` \| `Reverse` \| `Neutral` |
| `state_actor` | `string\|null` | `Driver` \| `Passenger` |
| `state_trust` | `string\|null` | Informational; the reference runner always uses `operator_trusted` for supplied state |
| `clock_offset_seconds` | `int` | Seconds to add to the current time before calling `decide()` |
| `phase2_grant_type` | `string\|null` | For two-phase vectors: `valid` \| `mismatched_hash` \| `expired` \| `wrong_binding_id` \| `bad_signature` |
| `gateway_test_type` | `string\|null` | For gateway vectors: `enforce` \| `forbidden_receipt` \| `replay` \| `stale` \| `deny_receipt` \| `tampered_tool` \| `no_binding` |

### `expected` fields

| Field | Type | Meaning |
|---|---|---|
| `verdict` | `string` | `ALLOW` \| `DENY` \| `EXPIRED` \| `PENDING_APPROVAL` |
| `policy_rule_contains` | `string\|null` | If set, `Verdict.policy_rule` must contain this substring |
| `gateway_enforced` | `bool\|null` | `true` = expect `Enforced`; `false` = expect `Refused` |
| `gateway_refused_reason_contains` | `string\|null` | If set, gateway refusal reason must contain this substring (case-insensitive) |

### Mandate construction

Vectors do not contain pre-signed mandate bytes. The runner constructs and signs a mandate at runtime from the `mandate_*` fields using freshly generated ephemeral keys. This is necessary because mandates embed timestamps that must be current at evaluation time.

**External implementations** must replicate this construction logic:

1. Generate an agent keypair and an issuer (sovereign) keypair.
2. Build a mandate TOML matching the `mandate_*` fields.
3. Sign with the implementation's signing procedure (see §4.5 of SPEC.md and Known Divergences below).
4. For `mandate_bad_signature: true`: tamper the signature hex bytes before evaluation.
5. For `mandate_use_spec_signing: true`: use the SPEC §4.5 canonical payload `MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>`.
6. For `clock_offset_seconds != 0`: add the offset to the evaluation clock.

---

## Conformance Levels

Three levels are defined in SPEC.md §10.

### Level 1 — Decision-conformant

The implementation passes all vectors in categories `01` through `07`:

| Category | Vectors | SPEC sections |
|---|---|---|
| 01 — verdict semantics | vs-001 to vs-008 | §2, §5 |
| 02 — forbidden first | ff-001 to ff-006 | §2.3, §5.3, §7.6 |
| 03 — mandate validation | mv-001 to mv-006 | §4, §5.5 |
| 04 — pipeline ordering | po-001 to po-009 | §5.2–§5.11 |
| 05 — attested state | as-001 to as-005 | §6 |
| 06 — two-phase HITL | tp-001 to tp-008 | §7 |
| 07 — receipt and ledger | rl-001 to rl-005 | §8 |

Known-failing vectors (`known_failing: true`) are excluded from this count; a Level 1 claim covers only the vectors that are _not_ known-failing. Known-failing vectors encode the _spec-correct_ expectation; divergences are documented in CONFORMANCE.md, not deleted or weakened.

### Level 2 — Gateway-conformant

Level 1 _plus_ all vectors in category `08`:

| Category | Vectors | SPEC sections |
|---|---|---|
| 08 — gateway contract | gc-001 to gc-007 | §9 |

### Level 3 — Full-conformant

Level 2 _plus_ implementation of all features marked SHOULD in SPEC.md §10.3, including multi-party delegation chains (§11) and the mandatory audit endpoint (§12).

---

## Claiming Conformance

To claim "A2G v1.0 conformant" at any level:

1. Run the conformance suite against your implementation.
2. All non-`known_failing` vectors for the claimed level must report `PASS`.
3. Any vectors you skip or fail must be documented in your implementation's conformance statement with the divergence reason.
4. Known-failing vectors (`known_failing: true` in the reference suite) may be skipped in your claim _only if_ the divergence is the same implementation gap documented here. If your implementation addresses the divergence, you must mark those vectors as expected to pass.

---

## Vector Categories

| Dir | Category | Count | Description |
|---|---|---|---|
| `01-verdict-semantics` | Core verdict outcomes | 8 | ALLOW / DENY / EXPIRED / PENDING_APPROVAL for each risk tier |
| `02-forbidden-first` | Forbidden-first guarantee | 6 | Forbidden fires before any mandate check, grant, or escalation |
| `03-mandate-validation` | Mandate signing and TTL | 6 | Signature check, TTL, spec vs. impl signing payload |
| `04-pipeline-ordering` | Step ordering | 9 | Each step fails in the correct order (pre-check → steps 0–7) |
| `05-attested-state` | Vehicle state gating | 5 | Fail-safe, operator_trusted, state_trust recording |
| `06-two-phase` | HITL two-phase protocol | 8 | Phase 1 binding, Phase 2 grant validation, parent_receipt_hash |
| `07-receipt-ledger` | Receipt chain integrity | 5 | Genesis hash, hash computation, tamper detection, state_trust |
| `08-gateway-contract` | Gateway 7-step verification | 7 | Forbidden re-check, sig, ALLOW-only, freshness, nonce, request_hash, binding |
| **Total** | | **54** | |

---

## Known Divergences

Vectors with `"known_failing": true` encode the _spec-correct_ expectation. The reference implementation currently diverges from those vectors. The divergences are documented here; they are not weakened or deleted from the suite.

### mv-004 — Mandate signing payload (§4.5)

**Vector:** `conformance/vectors/03-mandate-validation/mv-004.json`

**SPEC §4.5 specifies:**
```
MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>
```
where `capabilities_hash = SHA-256(sorted capabilities list joined by ",")`.

**Reference implementation uses:**
```
MANDATE:<re-serialized-body-toml>
```
The implementation hashes the full re-serialized mandate body (without the `[signature]` section) rather than the structured canonical fields specified in §4.5.

**Impact:** A mandate signed with the spec-canonical payload is rejected by the reference implementation with `mandate_invalid: signature error`. A mandate signed with the implementation payload (`MANDATE:<body>`) is accepted.

**Current status:** Known gap. Existing mandates produced by `a2g sign` remain valid and unaffected (they use the implementation format). Migration to the spec-canonical format requires a version bump and a re-sign migration path; this is tracked as a follow-on item in [docs/adr/](docs/adr/).

**Affected vectors:** mv-004 only. All other mandate-validation vectors exercise the implementation's actual signing path and pass.

---

## How to Add Vectors

1. Create a `.json` file in the appropriate `conformance/vectors/<category>/` directory.
2. Assign a sequential `id` (e.g. `vs-009`) and a `spec_ref` pointing to the SPEC.md section being tested.
3. Set `known_failing: true` with a `known_failing_reason` if the vector tests a spec requirement the implementation does not yet meet.
4. Run `cargo run -p a2g-conformance` to verify the vector parses and runs.
5. Submit via pull request; CI will gate on zero unexpected failures.
