# ADR-0007: Attested Vehicle State

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `docs/adr/attested-vehicle-state`

---

## Context

State-gating (Step 4.5, ADR-0005) decides ALLOW or DENY for Sensitive-domain tools based on vehicle state: `speed_kph` and `gear`. Today that state arrives via `--vehicle-state` (CLI flag) or VHAL telemetry polling and is passed directly to `decide()` without verification.

This is a **trust hole**.

### The attack

An adversary who can influence the state feed — by spoofing a VHAL read, injecting a stale cache entry, or replaying a previously-captured state message — can supply a vehicle state that reports `{speed_kph: 0.0, gear: "Park"}` while the car is travelling at 60 km/h. The result:

1. `decide()` receives state that passes the Sensitive gate: `speed_kph < 5.0 AND gear == Park` → gate OPEN.
2. `DOOR_LOCK` (unlock variant) reaches Step 6 (escalation) and, if approved, returns `ALLOW`.
3. The signed, hash-chained receipt records that the unlock was authorized.
4. The door unlocks at speed.

The ledger now contains **cryptographic evidence that a dangerous action was authorized** — because the garbage state that authorized it was never verified. Signed garbage in, signed garbage out.

A **correctly-signed but replayed or stale** state is the same attack: the attacker does not need to forge a signature — capturing and replaying a valid `{Park, 0 km/h}` state from a previous stopped interval is sufficient. Signature validity alone does not establish freshness.

### What decide() currently assumes

`decide()` is a pure function (ADR-0004). It accepts `vehicle_state` as a value and evaluates it — it has no mechanism to verify that value's provenance or age. The purity guarantee is correct; the trust boundary is not.

## Decision

**Vehicle state is treated as untrusted input until the calling layer attests it.**

### 1. The `decide()` core stays pure and agnostic

`decide()` does not change. It evaluates whatever state it is given. The contract is shifted: **callers must only supply verified state.** An unverified state value must never reach `decide()`.

This mirrors two precedents already established in the codebase:

- **Clock injection (ADR-0004):** `decide()` does not read the wall clock; the enforcing layer supplies the time. Trust-establishment for the clock lives at the boundary, not in the core.
- **Symlink resolution (ADR-0004):** `decide()` does not call `canonicalize`; `enforce()` resolves paths before the call. The I/O-boundary wrapper is the right place for trust-establishment.

Vehicle state verification follows the same pattern: the enforcing layer verifies, then calls `decide()`.

### 2. Verification requirements

State verification requires **both** of the following. Neither is sufficient alone.

**Attestation signature.** The `VehicleState` value must carry a signature from a trusted source — the VHAL HAL, a TEE, or a secure hardware element — over the state fields. The verifying component checks this signature against a known public key before passing state to `decide()`. A state value that fails signature verification is rejected; `decide()` is not called.

**Freshness token.** The state value must carry a freshness proof: either a nonce issued by the enforcing layer before the state request (challenge–response), or a monotonic hardware timestamp with a configured maximum age. The verifying component checks that the nonce matches its issued challenge or that the timestamp is within the freshness window. A valid signature on a stale state is rejected.

The combination of signature and freshness means:
- A spoofed state cannot pass (no signing key).
- A replayed valid state cannot pass (fails freshness check).

### 3. Verification lives in the trusted enforcing layer (roadmap gateway / TEE)

The component that verifies vehicle state is the **Secure Gateway** — the roadmap enforcing component that sits between the agent process and the VHAL HAL (noted as a roadmap item in the README and ADR-0005). The Secure Gateway:

1. Issues a nonce (or reads a monotonic counter) before requesting state from the VHAL HAL.
2. Requests a signed state bundle from the HAL (or TEE-resident sensor aggregator).
3. Verifies the attestation signature and the freshness proof.
4. Only on successful verification, extracts the `VehicleState` value and calls `decide()`.
5. On verification failure, emits `DENY` with `policy_rule = "unattested_vehicle_state"` and writes a receipt — the agent's request is blocked and the failure is auditable.

This keeps all I/O, all external trust decisions, and all cryptographic verification outside `decide()`. The core remains pure and embeddable.

### 4. Interim posture (before the gateway exists)

Until the Secure Gateway is a deployed runtime component, callers using `enforce()` directly (e.g., the CLI, integration tests) supply state via the `--vehicle-state` flag. This path is **operator-trusted**: the operator is responsible for supplying accurate state. The risk is documented here and in the CLI help text.

The fail-safe default (ADR-0005: omitted state → `VehicleState::fail_safe()` → Sensitive DENY) remains the floor. Omission cannot grant access; only a supplied (and, once the gateway exists, verified) state can do so.

## Consequences

### Positive

- The ledger's cryptographic evidence is sound: a signed receipt for an ALLOW on a Sensitive tool means the vehicle state was attested, not merely asserted.
- Replay attacks are closed: a valid state captured from a previous stopped interval cannot be used to authorize an action taken while moving.
- `decide()` requires no changes — the purity and embeddability guarantees of ADR-0004 are preserved.
- The verification architecture strengthens the security posture for OEM assessors and any future ISO 21434 / UNECE WP.29 alignment work.

### Neutral

- The Secure Gateway becomes the verification owner. Its implementation must cover: nonce issuance, HAL state request, signature verification, freshness check, and `decide()` invocation — in that order.
- The attestation key management (HAL signing key, TEE key provisioning) is out of scope for `a2g-core`; it is a platform concern for the gateway deployment.

### Negative / Residuals

- Until the gateway exists, the CLI path is operator-trusted. This is documented and accepted for the current development phase; it is not a regression from the pre-ADR-0007 state.
- A `VehicleState` type that carries an attestation signature is required before the gateway can verify it. This is a planned implementation item (a new signed wrapper type or an extension to the existing `VehicleState` struct). The implementation should be tracked as a follow-on to this ADR.

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Verify state inside `decide()` | Violates purity (requires cryptographic verification, which involves key material I/O); blocks `no_std` path; the core should not own trust decisions |
| Verify state inside `enforce()` | `enforce()` is already the std-layer I/O boundary, but it has no access to VHAL signing keys; key access belongs to the gateway, not the library |
| Accept state as trusted on the CLI path indefinitely | Leaves the trust hole open; a deployed gateway cannot be reasoned about if the design does not specify what "trusted" means |
| Freshness via wall clock only (no nonce) | A clock-based freshness check requires synchronized time between the HAL and the gateway; a nonce-based challenge–response does not |
| Signature alone without freshness | Insufficient — a valid captured state can be replayed; both are required |

## Open Questions

### Key provisioning for HAL attestation

The VHAL HAL signing key must be provisioned into the HAL firmware and its corresponding public key made available to the gateway verifier. This is a platform concern. The ADR does not specify a key distribution mechanism; that should be addressed in the gateway design specification.

### Freshness window duration

The maximum acceptable age for a timestamp-based freshness check (for deployments that cannot use challenge–response) should be configured per OEM. A reasonable starting point for discussion is 500 ms, but the appropriate value depends on the update rate of the HAL sensor aggregator and the latency budget of the enforcement path.

**Implementation note**: `a2g-core` exports `ATTESTATION_FRESHNESS_MS = 500` as a provisional default. This constant is explicitly provisional — it is intentionally placed in an open question rather than a decision. Callers should pass a deployment-specific `freshness_ms` to `AttestedVehicleState::verify()` rather than relying on this default.
