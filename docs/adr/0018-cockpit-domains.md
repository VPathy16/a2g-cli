# ADR-0018 — Cockpit Domain Extension: Communications, Payments, and PII

**Status:** Accepted  
**Date:** 2026-06-12  
**Replaces:** —  
**Related:** ADR-0005 (vehicle capability model), ADR-0008 (HITL), ADR-0013 (mandate CBOR), SPEC §3.5

---

## Context

A2G v0.2.0 governs in-cabin AI agents across the `vehicle.*` namespace.  As the
cabin environment matures, agents will request capabilities outside the vehicle
domain: placing calls, sending messages, reading contacts, initiating payments,
and accessing passenger profile data.

These actions share the physical-safety concern of `vehicle.*` (wrong action at
wrong moment = harm) but introduce a second concern: **personal-data privacy**.
A "read my contacts" action cannot crush a door on a passenger, but it can exfil
an entire address book to an unapproved third party — with no physical signal
to the occupant that it happened.

### Existing extension point

SPEC §3.5 (Profiles) reserves the namespace registry extension mechanism: new
capability namespaces may be added by defining a new profile and updating the
classification table.  This ADR uses that mechanism.

### Protocol-freeze constraint (v0.2.0)

The following MUST NOT change:

| Artefact | Why frozen |
|----------|-----------|
| `MandateTbs` CBOR array layout (indices 0–32) | Signed payload — any new index changes the bytes being signed, breaking all existing mandates |
| `CborMandate` envelope | Wire-transport layout; changing breaks all decoders |
| `BindingPayload` / `GrantPayload` | HITL signing surface |
| Receipt canonical bytes | Gateway enforcement protocol |
| Existing `Decision` / `Verdict` fields | Downstream consumers depend on these |

---

## Decision

### Three new namespaces

| Namespace | Examples | Classification |
|-----------|----------|---------------|
| `comms.*`  | `comms.call.place`, `comms.sms.send`, `comms.contacts.read`, `comms.history.read` | Sensitive class (see sub-table) |
| `pay.*`    | `pay.toll.charge`, `pay.parking.start`, `pay.subscription.manage` | Always-HITL Sensitive |
| `pii.*`    | `pii.contacts.read`, `pii.location.read`, `pii.profile.read`, `pii.profile.export` | PII-gated; `pii.profile.export` is Forbidden |

#### comms.* sub-classification

| Tool | Classification |
|------|---------------|
| `comms.call.place` | `CommsSensitiveHitl` — places a call; always requires HITL |
| `comms.sms.send`   | `CommsSensitiveHitl` — sends a message; always requires HITL |
| `comms.contacts.read` | `CommsReadPiiGated` — reads address book; requires `pii.grant` |
| `comms.history.read`  | `CommsReadPiiGated` — reads call/message log; requires `pii.grant` |
| Unknown `comms.*`  | `SensitiveHitlUnknown` — fail-closed forward-compat |

#### pii.* sub-classification

| Tool | Classification |
|------|---------------|
| `pii.profile.export` | **Forbidden** — structural hard DENY (same tier as ADAS writes) |
| `pii.*.read` (any sub-path ending in `.read`) | `PiiReadGated` — requires `pii.grant` |
| Unknown `pii.*`  | `SensitiveHitlUnknown` — fail-closed |

### Enforcement rules added to `decide_core()`

1. **Cockpit Forbidden pre-check** — immediately after the Vehicle Forbidden
   pre-check.  `pii.profile.export` is denied before any mandate evaluation.
   No approval grant can override this (same guarantee as `CRUISE_CONTROL_COMMAND`).

2. **PII grant check (Step 3.5)** — after tool authorization.  Tools in
   `PiiReadGated` or `CommsReadPiiGated` require the mandate to carry the
   sentinel capability `"pii.grant"` in its `tools` list.  Without it → DENY
   with policy rule `pii_grant_required`.

3. **Always-HITL in Step 6** — tools in `PayAlwaysHitl`, `CommsSensitiveHitl`,
   or `SensitiveHitlUnknown` always generate a `PendingApproval` verdict even
   if they are not listed in `escalate_tools`.  This is implemented by treating
   these domains identically to the `escalate_tools` branch.

4. **Unknown cockpit namespace** — any `comms.*`, `pay.*`, or `pii.*` tool that
   does not match a known specific pattern resolves to `SensitiveHitlUnknown`
   and is therefore always-HITL.  This closes the forward-compat gap:
   future tools default to human approval, not silent allow.

### `pii.grant` as a capability sentinel (protocol-freeze compliant)

The protocol freeze prohibits adding new fields to `MandateTbs`.  However,
`MandateTbs` already carries a `tools: Vec<String>` list (index 9) that
represents the set of capabilities the mandate grants.  A sentinel string
`"pii.grant"` is a valid entry in this list — it is not a callable tool but
a capability token the enforcement engine checks for.

This approach:
- Requires **no change** to `MandateTbs` or its CBOR encoding.
- Is backward-compatible: existing mandates without `"pii.grant"` simply cannot
  call pii-gated tools, which is the correct deny-by-default behavior.
- Is forward-compatible: mandate issuers explicitly opt in by including `"pii.grant"`.

### Why `pii.profile.export` is Forbidden (not Sensitive-HITL)

A HITL approval enables one specific action in one session.  An export of a
complete passenger profile creates a persistent artefact that leaves the vehicle.
The harm is irreversible; no vehicle context (parked, owner present) reduces the
risk after export.  HITL approval would give false assurance that the occupant
reviewed and understood the full content of the export — that bar cannot be met
through a push notification.  Therefore export is denied at the structural level.

---

## Consequences

### What changes

- New `cockpit` module in `a2g-core` with `CockpitDomain` enum and
  `classify_cockpit_tool()`.
- Three new pre/post-authorization checks in `decide_core()` — the Forbidden
  pre-check ordering is preserved (vehicle forbidden fires before cockpit forbidden).
- Conformance suite extended with 12+ new vectors in `10-cockpit-domains/`.
- Adversarial suite extended with attacks 12 (pay.* bypass), 13 (pii export
  bypass), 14 (pii grant forgery).

### What does NOT change

- `MandateTbs`, `CborMandate`, `BindingPayload`, `GrantPayload` — no changes.
- `VehicleDomain` enum — no changes.
- `decide()` and `decide_with_approval()` public signatures — no changes.
- `Verdict` fields — no changes.
- Existing conformance vectors — zero diffs.

### Open questions

1. **Comms state gating**: Should `comms.call.place` be denied while the vehicle
   is moving (hands-free call initiation while driving)?  This ADR defers that
   question — HITL provides a human-approval gate which is sufficient for now.
   A future ADR may add `speed_mmps >= SPEED_GATE_MMPS → DENY` for comms-call.

2. **pii.grant per-category granularity**: The current design uses a single
   `"pii.grant"` token.  A future extension could use `"pii.contacts.grant"`,
   `"pii.location.grant"`, etc. for finer-grained control.  The sentinel
   approach adopted here does not preclude this — add more sentinel names.

3. **pay.* rate limiting**: Payment tools currently use the mandate-level
   `max_calls_per_minute` rate limit.  A per-session or per-day payment cap
   may be desirable; deferred to a future ADR.

4. **Actor-aware comms HITL** *(recorded deviation)*: The task specification
   called for actor-aware gating on `comms.call.place` / `comms.sms.send` —
   agent-initiated invocations would require HITL; driver-initiated (voice
   command) would not.  The implementation chose **always-HITL regardless of
   initiator** (fail-closed direction).  This is acceptable from a security
   posture but creates an HMI safety issue: a driver saying "call my wife"
   receives an approval-prompt interruption while driving, which is itself a
   distraction finding.  A future ADR should introduce an `actor` field in
   attested state and gate `CommsSensitiveHitl` tools on
   `actor == AgentInitiated` before requiring HITL.  Filed as follow-up:
   "actor-aware comms HITL".

5. **pii-gated reads trust model residual risk**: `comms.contacts.read` and
   `pii.*.read` tools are enforced by `decide_core()` in the rich domain.
   The gateway does **not** have an independent binding guard for these tools
   (only `pay.*` and other always-HITL tools have the Step 3.5 binding check).
   A compromised rich-domain agent that holds the gateway receipt-signing key
   can issue a validly-signed ALLOW receipt for `comms.contacts.read` without
   ever calling `decide()` — the gateway will pass it through.  This is
   consistent with the existing trust model for `Sensitive` tools (the same
   exposure exists for any Sensitive vehicle tool), but it is a residual risk
   worth making explicit.  Mitigation path: mandate-presentation-at-enforcement
   mode (the gateway verifies the mandate independently, not just the receipt
   signature) — deferred to a future ADR.
