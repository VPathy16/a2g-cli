# ADR-0010 — Enforcing Gateway

**Status**: Accepted  
**Date**: 2026-06-04  
**Context**: a2g-core, a2g-ffi, vehicle bus integration  
**Closes open items in**: ADR-0007 §"state verifier deferred", ADR-0008 §"pending queue deferred to infrastructure", ADR-0009 §"binding key is in-process interim"

---

## Context

ADRs 0007–0009 collectively implement a cryptographic decision pipeline: attested vehicle state, two-phase human-in-the-loop approval, and a C-ABI FFI layer. Each ADR deferred a structural problem with the note "resolved by the gateway." This ADR names and specifies that gateway.

The unresolved problem has three facets:

**1. Verdicts are advisory.** `a2g-core::decide()` produces a `Verdict`, but the verdict is not mechanically binding. Nothing in the current architecture prevents a host process from receiving `DENY` and writing to the vehicle bus anyway. The decision and the enforcement are co-located in the same trust domain; a compromised or misbehaving rich-side process can bypass the policy engine entirely.

**2. Three artifacts have no verified owner.**

- The binding-signing key (ADR-0009) lives inside the agent process on an ephemeral `OnceLock`. This is labeled "interim" in ADR-0009 because it means the process that requests an action also holds the key that authorizes it — a circular trust assumption.
- Vehicle-state attestation (ADR-0007) has a verifier signature (`AttestedVehicleState::verify()`), but ADR-0007 explicitly defers the question of *who* calls that verifier to "the gateway."
- The HITL pending-approval queue (ADR-0008) is specified as a first-class artifact but has no designated owner; ADR-0008 defers it to "infrastructure."

**3. The forbidden check is single-point-of-trust.** The hard-deny list (`enforce.rs` §forbidden domain) runs inside `a2g-core`, which runs inside the rich domain. A compromised rich domain can skip the check. Defense in depth requires an independent forbidden re-check that the rich domain cannot bypass.

---

## Decision

Introduce an **Enforcing Gateway**: a separate trust domain that is the sole path from the agent side to the vehicle bus. The agent and `a2g-core` propose and decide; the gateway verifies and enforces.

The gateway is not a second policy engine. It does not re-run the full 8-step mandate evaluation. Its job is narrower and harder: verify that a decision was made correctly, re-check the single invariant that must never be bypassed (the forbidden domain), and be the only writer to the bus.

---

## Trust Model and Domains

### Two domains

| Domain | Members | Trust assumption |
|---|---|---|
| **Rich domain** | LLM/agent, `a2g-core`, `a2g-ffi`, host application | Untrusted from the gateway's perspective. May be compromised, misconfigured, or actively adversarial. |
| **Trusted domain** | The gateway process/partition | Trusted. Minimal attack surface. No LLM, no agent logic, no network connectivity other than the approval channel. |

The gateway treats **all input from the rich domain as untrusted**. A receipt signed by a key the gateway does not recognize is rejected. A receipt claiming `ALLOW` for a forbidden capability is rejected even if the signature is valid. The rich domain cannot instruct the gateway to act; it can only present evidence that the gateway independently verifies.

### Isolation spectrum

The interface between the two domains is identical regardless of isolation depth. This means isolation can harden incrementally without rearchitecting the protocol:

| Deployment tier | Isolation mechanism | Notes |
|---|---|---|
| Demo / development | Separate OS process on the same host | Low barrier; useful for integration testing |
| Integration / pre-production | Hypervisor partition or container with hardware-enforced memory isolation | Rich domain cannot read gateway memory |
| Production | Separate safety MCU or HSM-backed secure enclave | Rich domain has no code path to gateway memory or bus hardware |

The wire protocol (§Signed-Receipt Protocol below) is the same in all tiers. Hardening the isolation boundary does not require changes to `a2g-core`, `a2g-ffi`, or the agent.

---

## The Signed-Receipt Protocol

This is the core contract between the two domains.

### Message structure

When `a2g-core` produces a verdict, the rich domain packages a **Gateway Receipt** and submits it to the gateway. The gateway either enforces the action (writes to the bus) or rejects it silently — producing no bus traffic.

A Gateway Receipt contains the following fields:

```
GatewayReceipt {
    verdict_id:      UUID          // from Verdict.id
    decision:        enum          // ALLOW | DENY | EXPIRED | PENDING_APPROVAL
    tool:            string        // the tool/action name
    params_json:     string        // the parameters exactly as submitted to decide()
    policy_rule:     string        // from Verdict.policy_rule
    state_trust:     string        // "attested" | "operator_trusted" | "none"
    binding_id:      string        // present when decision is ALLOW following Phase 2
    request_hash:    string        // SHA-256 of (tool || params_json || timestamp_ms)
    issued_at_ms:    i64           // Unix milliseconds; used for freshness check
    nonce:           bytes[16]     // random; used for anti-replay
    signature:       bytes[64]     // ed25519 over the canonical payload (see below)
}
```

### Signed payload (canonical form)

The signature covers a deterministic serialization of the receipt fields that affect the enforcement decision. The gateway recomputes this payload and verifies the signature before doing anything else:

```
RECEIPT:{verdict_id}:{decision}:{tool}:{request_hash}:{binding_id}:{issued_at_ms}:{nonce_hex}
```

Fields not in the payload (e.g. `params_json`, `policy_rule`) are verified separately: `request_hash` is `SHA-256(tool || params_json || issued_at_ms)`, so the gateway can verify that `params_json` matches the hash without including the full body in the signed string.

### Signing key

The gateway holds the signing key. The rich domain holds the corresponding **verifying key** only — it can construct a receipt but it cannot forge the gateway's own signatures, and the gateway's trust decision is never based on a key it issued to the rich domain.

For the Phase-2 flow, the gateway also holds the **binding-signing key** (closing ADR-0009's in-process interim). Phase 1 receipts are signed by the gateway's binding key; Phase 2 re-entry presents the signed binding back to the gateway, which verifies it before assembling the Phase 2 Gateway Receipt.

### Gateway verification steps

The gateway performs the following checks in order. Any failure terminates the request; no bus write occurs.

1. **Signature valid** — verify the ed25519 signature against the canonical payload using the known rich-domain receipt-signing key.
2. **Decision is ALLOW** — only `ALLOW` receipts proceed. `DENY`, `EXPIRED`, `PENDING_APPROVAL`, and `ERROR` are all rejected.
3. **Freshness** — `issued_at_ms` must be within an implementation-defined window (provisionally 2 seconds) of the gateway's clock. Receipts outside this window are rejected regardless of signature validity.
4. **Nonce not seen** — the nonce must not appear in the gateway's recent-nonce ring buffer. This prevents replay of a valid ALLOW receipt for a different action invocation.
5. **Action match** — `tool` and `SHA-256(tool || params_json || issued_at_ms)` must match `request_hash`. This ensures the receipt covers exactly the action being presented, not a different one.
6. **Binding match** (Phase 2 only) — `binding_id` must match a pending-approval entry in the gateway's queue, and the `request_hash` in the binding must match the receipt's `request_hash`.
7. **Independent forbidden re-check** — see §Independent Forbidden Re-Check below.

Only after all seven checks pass does the gateway write to the bus.

### Wire format

For the demo tier, receipts are exchanged as JSON over a Unix domain socket (`/run/a2g-gateway.sock`). The format is intentionally not committed to in this ADR beyond the field names above; a future ADR may specify CBOR over CAN TP for production use. The fields and their semantics are stable regardless of encoding.

---

## Independent Forbidden Re-Check

The gateway maintains its own copy of the forbidden-domain list. This list is identical in content to the one in `a2g-core` (`enforce.rs` §forbidden domain), but the gateway's copy is consulted independently, after signature verification.

**Even a validly-signed ALLOW receipt for a forbidden capability is refused at the gateway.**

The rich domain is never trusted to have performed the forbidden check correctly. This provides defense in depth against:

- A bug in `a2g-core` that causes a forbidden tool to be evaluated in the wrong domain.
- A compromised rich domain that constructs a receipt for a forbidden action and obtains a valid signature by presenting it to a complicit signer.
- A future mandate-configuration error that accidentally lists a forbidden tool in an ALLOW scope.

The gateway's forbidden list is updated only through the gateway's own configuration path, which is outside the rich domain's write access.

---

## Key Ownership

### Binding-signing key (closes ADR-0009 §interim)

ADR-0009 introduced a per-process ephemeral `ed25519` key (`OnceLock<SigningKey>`) to MAC-protect the Phase-2 binding JSON. That key living in the rich domain is an interim measure: the process that requests approval also holds the key that authenticates the binding.

In the gateway model, the binding-signing key moves into the gateway. The rich domain sends an unsigned Phase-1 result to the gateway; the gateway signs the binding and returns the MAC-protected blob. The rich domain holds the signed blob opaquely and passes it back on Phase-2 entry. The gateway verifies its own signature.

The `OnceLock<SigningKey>` in `a2g-ffi` remains functional for the demo tier (single-process with no gateway deployed) and should be labeled clearly as "demo only" once the gateway tier is available.

### Vehicle-state attestation key (closes ADR-0007 §verifier deferred)

ADR-0007 specifies `AttestedVehicleState::verify(public_key, attestation, freshness_ms)` but defers the question of who calls it and who holds the key. The gateway is that verifier.

Vehicle state arrives at the gateway pre-signed by the sensor/ECU that produced it. The gateway verifies the attestation against the known ECU public key before including the state in any enforcement decision. Only verified, fresh state can produce `state_trust = "attested"` in a receipt the gateway accepts. State that fails attestation verification is treated as `state_trust = "none"`, which the independent forbidden check and the DENY-by-default for sensitive actions will catch.

### Key provisioning

| Tier | Key storage | Acceptable? |
|---|---|---|
| Demo | Ephemeral in-memory keys, regenerated on gateway restart | Yes — clearly labeled as demo |
| Pre-production | Keys stored on-disk in a protected filesystem partition, loaded at startup | Acceptable with documented threat model |
| Production | HSM or vehicle-grade secure element; key material never in RAM in plaintext | Required |

The gateway must refuse to start in production mode without a properly provisioned key store. The distinction between demo and production modes must be explicit in the gateway's configuration and visible in the receipt's `state_trust` field.

---

## HITL Pending Queue Ownership

ADR-0008 specifies the two-phase approval flow and the `PendingApprovalBinding` / `ApprovalGrant` data model, but explicitly defers the pending queue to "infrastructure."

The gateway owns the pending-approval queue. Concretely:

1. When `a2g-core` returns `PENDING_APPROVAL`, the rich domain presents the unsigned Phase-1 output to the gateway.
2. The gateway signs the binding (using its binding-signing key), stores the `(binding_id → SignedBinding)` entry in its pending queue with a TTL, and returns the signed binding to the rich domain.
3. The gateway drives the human-facing approval prompt (out of scope for this ADR in terms of UI mechanism, but the prompt includes the tool name, params summary, escalate-to authority, and TTL).
4. The human operator reviews and produces a signed `ApprovalGrant` (signed with the operator's own key, covering `binding_id`, `request_hash`, and `expires_at`).
5. The gateway verifies the `ApprovalGrant` signature against the known operator key and checks that `binding_id` matches a live queue entry and that the grant has not expired.
6. Only then does the gateway permit a Phase-2 receipt (with matching `binding_id`) to pass through to the bus.
7. Entries in the pending queue that expire without a grant are dropped; a subsequent Phase-2 attempt returns `EXPIRED`.

The rich domain never polls the pending queue directly. It submits Phase-2 receipts; the gateway knows whether the corresponding binding has been approved.

---

## The Bus Interface

The gateway is the **only writer** to the vehicle bus. No path from the rich domain to the bus hardware exists that does not pass through the gateway. This is an architectural invariant, not a software policy.

### Demo tier: simulated bus (SocketCAN vcan)

For the demo, the gateway writes enforced ALLOWs to a SocketCAN virtual CAN interface (`vcan0` on Linux). Observable effects:

- An enforced ALLOW produces a CAN frame on `vcan0` observable with `candump`.
- A rejected action (DENY, EXPIRED, forbidden re-check failure, signature failure) produces no CAN frame.
- The absence of a frame is as meaningful as its presence — the demo surface area is intentionally minimal.

Setup: `modprobe vcan && ip link add dev vcan0 type vcan && ip link set up vcan0`.

CAN frame content for the demo: a fixed-format 8-byte frame carrying `(verdict_id[4..8], tool_hash[0..4])` is sufficient to prove the action reached the bus. The exact frame format is out of scope for this ADR.

### Production path

Production deployment targets real CAN (ISO 11898) or automotive Ethernet (SOME/IP, DoIP) depending on the vehicle architecture. The gateway's bus-write path will be replaced with the appropriate hardware driver. The receipt protocol and verification logic are unchanged.

---

## What the Gateway Does NOT Do

To keep the separation crisp:

- **Does not decide policy.** The gateway does not evaluate mandates, domains, jurisdiction, or any of `a2g-core`'s 8 steps. It verifies that `a2g-core` decided correctly and that the receipt is authentic.
- **Does not run the agent or LLM.** The gateway has no awareness of the agent that originated the request.
- **Does not trust the rich domain's verdict blindly.** The gateway re-verifies the receipt independently. A verdict from `a2g-core` is necessary but not sufficient.
- **Does not produce verdicts.** If the gateway rejects a receipt, it does not substitute a different verdict. It produces no output to the bus.
- **Does not store audit logs.** Audit logging remains the responsibility of `a2g-cli`'s SQLite ledger (the rich domain). The gateway's authoritative record is the bus traffic itself.

---

## End-to-End Sequence: Sensitive Action (Two-Phase)

The following sequence traces a request for `WINDOW_POS` (window position control), a sensitive tool that requires human approval when the vehicle is in motion.

```
Agent                    a2g-core (rich)          Gateway (trusted)        Human operator
  |                           |                        |                        |
  |-- decide(WINDOW_POS) ---->|                        |                        |
  |                           |-- evaluate mandate --->|                        |
  |                           |   (all 8 steps)        |                        |
  |                           |<-- PENDING_APPROVAL ---|                        |
  |                           |   + unsigned binding   |                        |
  |                           |                        |                        |
  |<-- PENDING_APPROVAL ------| (rich domain forwards) |                        |
  |   + unsigned binding      |                        |                        |
  |                           |                        |                        |
  |--- present binding -------------------------------->|                        |
  |                           |                        |-- sign binding ------->|
  |                           |                        |-- store in queue ----->|
  |                           |                        |-- prompt operator ---->|
  |<--- signed binding --------------------------------|                        |
  |    (MAC-protected blob)   |                        |                        |
  |                           |                        |   (operator reviews)   |
  |                           |                        |<-- signed grant -------|
  |                           |                        |   (ApprovalGrant)      |
  |                           |                        |                        |
  |                           |                        |-- verify grant sig --->|
  |                           |                        |-- check binding_id --->|
  |                           |                        |-- check grant TTL  --->|
  |                           |                        |-- mark approved ------>|
  |                           |                        |                        |
  |--- decide_with_approval ->|                        |                        |
  |    (signed binding +      |                        |                        |
  |     approval grant)       |                        |                        |
  |                           |-- Phase 2 evaluate --->|                        |
  |                           |   (verify grant,       |                        |
  |                           |    check binding hash) |                        |
  |                           |<-- ALLOW receipt ------|                        |
  |<-- ALLOW ---------------  |                        |                        |
  |                           |                        |                        |
  |--- present ALLOW receipt ------------------------>|                        |
  |   (signed GatewayReceipt) |                        |                        |
  |                           |                        |-- 1. verify sig        |
  |                           |                        |-- 2. decision == ALLOW |
  |                           |                        |-- 3. freshness check   |
  |                           |                        |-- 4. nonce not seen    |
  |                           |                        |-- 5. action match      |
  |                           |                        |-- 6. binding match     |
  |                           |                        |-- 7. forbidden re-check|
  |                           |                        |   WINDOW_POS: not      |
  |                           |                        |   forbidden → pass     |
  |                           |                        |                        |
  |<-- enforced ---------------------------------- write to vcan0 ------------->
```

If at any point verification fails (e.g., the agent presents a receipt for `BRAKE_OVERRIDE`, which is in the forbidden domain), step 7 rejects it and the bus write does not occur, regardless of the ALLOW in the receipt.

---

## Relationship to Prior ADRs

| ADR | Open item | Resolution in this ADR |
|---|---|---|
| ADR-0007 | "The gateway verifies attestation; the verifier is deferred." | §Key Ownership: the gateway is the designated attestation verifier. |
| ADR-0008 | "The pending-approval queue is deferred to infrastructure." | §HITL Pending Queue Ownership: the gateway owns the queue, drives the approval prompt, and verifies the grant before allowing Phase 2. |
| ADR-0009 | "The binding-signing key is in-process (interim)." | §Key Ownership: the binding key moves into the gateway; the `OnceLock<SigningKey>` in `a2g-ffi` is demo-only. |

---

## Consequences

- Any language or platform that can open a Unix domain socket and produce an ed25519-signed receipt can use the enforcement engine. The FFI layer (ADR-0009) remains the rich-domain interface; the gateway protocol is the enforcement interface.
- `a2g-core` requires no changes. The gateway consumes its output; it does not modify its internals.
- Deployers must provision the gateway correctly (key storage, bus access, forbidden list). A misconfigured gateway does not reduce safety below the current advisory-verdict baseline, but it does not improve it either.
- The demo tier (single process, ephemeral keys, `vcan0`) is sufficient to demonstrate the full protocol and produce observable bus traffic. It is not sufficient for production deployment.
- A compromised gateway is a full bypass: an attacker with gateway-level access can write to the bus without any receipt. This is addressed by the isolation spectrum (§Trust Model) — the production MCU/secure-enclave tier makes the gateway's attack surface hardware-constrained.

---

## Residual Limitations

**Compromised gateway.** The gateway's security properties depend on its own integrity. In the demo tier, gateway and rich domain share an OS; a root-level compromise defeats the isolation. This is known and acceptable for the demo. Production deployment must use the hypervisor-partition or separate-MCU tier.

**Demo key management is not production key management.** Ephemeral in-memory keys regenerated on restart provide no meaningful key continuity, revocation, or rotation. They are sufficient for local testing. Any deployment where key material persists across restarts requires a formal key-management process outside the scope of this ADR.

**Clock synchronization.** The freshness check depends on the gateway's clock being within the freshness window of the rich domain's clock. In a same-process demo this is trivially true; in a separate-MCU deployment, clock skew must be managed (e.g., via a secure time source).

**Pending queue persistence.** In the current specification the gateway's pending-approval queue is in-memory. A gateway restart drops all pending bindings. Production deployments requiring durability must add persistent queue storage; this is deferred to an implementation ADR.

---

## Open Questions

- **Receipt transport in production.** The Unix domain socket is appropriate for the demo. The production transport (CAN TP frame, dedicated automotive Ethernet channel, or shared in-vehicle network segment) is deferred to the deployment ADR for each vehicle platform.
- **Operator identity in the approval grant.** The current `ApprovalGrant` model (ADR-0008) specifies a signed grant but does not mandate a particular operator key infrastructure. Production deployment will require a defined operator PKI (certificate, revocation, delegation). This is deferred.
- **Multi-gateway topologies.** Some vehicle architectures have zone controllers, each controlling a subset of the bus. Running one gateway per zone vs. one central gateway is an open architectural question for production deployment.
