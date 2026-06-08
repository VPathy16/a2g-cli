# A2G Protocol Specification v1.0-draft

**Title:** A2G Protocol Specification — Agent-to-Governance Authorization Protocol  
**Version:** 1.0-draft  
**Status:** Draft — not yet normative  
**Authors:** Victor Pathy and Claude (Anthropic)  
**License:** Open specification — independent implementations are encouraged  

> This document is an open specification. It defines the A2G protocol as an
> implementation-independent standard. The Rust codebase in this repository is
> one conformant implementation. A reader with no access to the source SHOULD be
> able to build an interoperable A2G enforcement point and verify A2G receipts
> from this document alone.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Table of Contents

1. [Scope and Model](#1-scope-and-model)
2. [Verdict Semantics](#2-verdict-semantics)
3. [Capability Addressing](#3-capability-addressing)
4. [Mandate Format](#4-mandate-format)
5. [Decision Pipeline](#5-decision-pipeline)
6. [Attested State](#6-attested-state)
7. [Two-Phase Approval](#7-two-phase-approval)
8. [Receipt and Ledger](#8-receipt-and-ledger)
9. [Enforcement Contract](#9-enforcement-contract)
10. [Conformance](#10-conformance)
11. [Security Considerations](#11-security-considerations)
12. [References](#12-references)
13. [Appendix A — Implementation Status](#appendix-a--implementation-status)
14. [Appendix B — Design Rationale Cross-References](#appendix-b--design-rationale-cross-references)

---

## 1. Scope and Model

### 1.1 Purpose

A2G (Agent-to-Governance) is an authorization protocol for AI agent tool calls.
It answers the question: "Is this agent permitted to perform this action, at this
moment, given the current system state?" and produces a tamper-evident receipt
for every answer.

A2G is not a detection layer. It does not analyze output after execution. It
authorizes before execution.

### 1.2 Roles

**Proposer** (also: Agent)  
The entity requesting an action. Submits a capability identifier and parameters
to the Decision Engine. The Proposer is untrusted from the perspective of every
other component.

**Decision Engine**  
Evaluates a mandate against the requested action and produces a Verdict. The
Decision Engine MUST be a pure, deterministic function: given the same inputs it
MUST produce the same Verdict. It MUST NOT make I/O calls, read wall-clock time,
or produce side effects. All external inputs (clock, ledger state, system state)
MUST be injected explicitly by the caller.

**Enforcing Gateway**  
A component in a separate trust domain from the Proposer and Decision Engine. It
receives a signed receipt of an ALLOW verdict and — after independent
verification — performs the action on the protected resource (e.g., writes to
the vehicle bus). The Enforcing Gateway is the sole authorized writer to the
protected resource.

**Authority**  
An entity whose signed mandate defines what a specific Proposer is permitted to
do. The Authority's signing key is the root of trust for capability authorization.
Multiple Authorities MAY form a delegation chain.

### 1.3 Propose-Decide-Enforce Model

```
  Proposer
     │  capability + params
     ▼
  Decision Engine  ──  mandate  ──  Authority
     │
     │  Verdict + signed Receipt
     ▼
  Enforcing Gateway
     │  (independent verification)
     ▼
  Protected Resource
```

The model has three strict phases:

1. **Propose:** The Proposer identifies a capability to invoke and supplies
   parameters. The Proposer plays no further role.

2. **Decide:** The Decision Engine evaluates the mandate, capability, parameters,
   and any attested system state. It returns a Verdict and a signed Receipt. No
   side effect occurs.

3. **Enforce:** The Enforcing Gateway independently verifies the Receipt and, if
   all checks pass, performs the action. If any check fails, no action is taken
   and no bus write occurs.

### 1.4 Core Invariants

1. **The Decision Engine is pure.** `decide()` is a bounded-time, deterministic
   function. It MUST NOT read wall-clock time, file system state, or any external
   resource during evaluation. The caller MUST inject all such values explicitly.

2. **Enforcement is a separate trust domain.** The Enforcing Gateway MUST operate
   in a trust domain that the Proposer and Decision Engine cannot influence.
   Isolation depth is deployment-specific (see §9.2), but the protocol contract
   is identical at all isolation levels.

3. **A Verdict is advisory until enforced.** An ALLOW verdict produced by the
   Decision Engine does not by itself authorize an action. Only a successful
   Enforcing Gateway verification produces a bus write. An ALLOW receipt that
   fails gateway verification MUST result in no action.

4. **The Forbidden classification is non-overridable.** A capability classified
   as Forbidden MUST be denied unconditionally. No mandate permission, escalation
   grant, attested state, or approval token can override a Forbidden
   classification. This check MUST execute before any mandate evaluation.

---

## 2. Verdict Semantics

### 2.1 Verdict Values

A Verdict is one of four values:

**ALLOW**  
The Decision Engine has evaluated all applicable checks and the action is
permitted. An ALLOW Verdict MUST carry a signed Receipt. An ALLOW Verdict MUST
NOT be produced for a Forbidden-domain capability.

**DENY**  
The action is not permitted. A DENY Verdict MUST carry a signed Receipt
explaining the reason. DENY is terminal: the action MUST NOT proceed.

**EXPIRED**  
The mandate's time-to-live has elapsed. Semantically equivalent to DENY for
enforcement purposes. A distinct value is preserved so that audit tools can
distinguish expiry from policy denial.

**PENDING_APPROVAL**  
The capability requires human authorization before it may proceed. The action
MUST NOT proceed based on a PENDING_APPROVAL verdict alone. The Verdict MUST
carry a `PendingApprovalBinding` (§7.2). A second `decide()` call with a valid
`ApprovalGrant` is required to produce ALLOW.

### 2.2 Exact Conditions

| Verdict | Condition |
|---------|-----------|
| DENY (forbidden) | Capability is in the Forbidden domain (§3.3). Fires before any other check. |
| DENY (revoked) | Mandate has been revoked in the ledger. |
| DENY (signature) | Mandate signature does not verify. |
| EXPIRED | Current time is at or after `mandate.expires_at`. |
| DENY (tool) | Capability identifier is not in `mandate.capabilities.tools`. |
| DENY (boundary) | Request parameters violate a filesystem, network, or command boundary. |
| DENY (state) | Capability is Sensitive-domain and verified state does not satisfy the state gate (§6.4). |
| DENY (jurisdiction) | Current time is outside `mandate.jurisdiction.operating_hours`. |
| PENDING_APPROVAL | Capability is in `mandate.escalation.escalate_tools` and no valid grant has been supplied. |
| DENY (rate) | Call count in the recent window exceeds `mandate.rate_limit`. |
| ALLOW | All of the above checks pass. |

The ordering of these conditions is normative — see §5.

### 2.3 Forbidden is Non-overridable

A DENY produced by the Forbidden pre-check MUST NOT be overridden by:

- A mandate that explicitly lists the capability in `capabilities.tools`
- An `ApprovalGrant` from any authority
- Attested state showing any physical condition
- Any other protocol mechanism

This constraint is structural. A conformant implementation MUST evaluate the
Forbidden classification before parsing or evaluating any mandate field.

---

## 3. Capability Addressing

### 3.1 Namespace

A capability identifier (also: tool name, action) MUST be a non-empty UTF-8
string. No maximum length is mandated by this specification; implementations
SHOULD enforce a practical limit and MUST document it.

The canonical form for structured capabilities is:

```
<domain>.<subject>.<action>
```

Where:
- `<domain>` is a top-level governance domain (e.g., `vehicle`, `file`, `network`)
- `<subject>` is the sub-system or resource (e.g., `climate`, `door`, `config`)
- `<action>` is the operation (e.g., `set_temperature`, `unlock`, `read`)

Additional dotted segments are permitted. The classifier MUST treat unknown
sub-domains within a known domain as the most restrictive risk tier applicable
to that domain.

Profile-defined identifiers (§3.5) MAY use alternative naming conventions within
their profile namespace.

### 3.2 Risk-Tier Model

Every capability identifier MUST be classified into exactly one risk tier before
any mandate evaluation. Classification MUST be independent of the mandate
contents and MUST be performed prior to mandate parsing.

The four normative risk tiers are:

**Comfort**  
Capabilities with no material safety consequence. Default verdict is ALLOW.
Vehicle state gating does not apply. Examples: cabin climate, seat position, in-cabin media.

**Convenience**  
Capabilities with minor safety consequence. Default verdict is ALLOW. Light state
gating MAY apply per profile. Examples: navigation input, communication.

**Sensitive**  
Capabilities that are safe only under specific physical conditions. Default
verdict is PENDING_APPROVAL (escalate). State gating MUST apply: an unverified
or absent state MUST produce DENY, not ALLOW. Examples: doors, windows, trunk,
locks.

**Forbidden**  
Capabilities that MUST NEVER be granted by any mandate. Default verdict is DENY,
produced before any mandate check. State gating does not apply — there is no
state that can make a Forbidden action permissible. Examples: propulsion control,
braking systems, ADAS commands, steering actuation.

### 3.3 Classification Rules

1. Classification MUST be performed by a dedicated classifier function that takes
   only the capability identifier string as input.
2. The classifier MUST be allocation-free, panic-free, and bounded in execution
   time (no recursion, no dynamic allocation).
3. The classifier MUST be safe to call on unverified, untrusted, or malformed
   input. An arbitrarily long or unusual capability identifier MUST NOT cause
   panic, hang, or over-allocation.
4. Classification MUST be deterministic: the same input MUST always produce the
   same risk tier.
5. An unknown capability identifier that does not match any domain prefix MUST be
   classified as at most Convenience. An unknown `vehicle.*` sub-domain MUST be
   classified as Sensitive (fail-safe).

### 3.4 Access-Mode Independence

The risk tier of a capability MUST be independent of the access mode (read vs.
write vs. subscribe). A profile that distinguishes read-only telemetry from
write-capable actuator commands MUST define separate capability identifiers for
each access mode, not rely on access-mode suffixes to alter classification.

Read-only telemetry identifiers that carry no safety-critical write path SHOULD
be classified as at most Convenience.

### 3.5 Profiles

A profile is a named set of rules that maps profile-specific capability
identifiers to risk tiers and MAY define additional constraints (e.g., state-gate
conditions, rate limits, VHAL property bindings).

A profile MUST specify:
- The domain namespace it extends or replaces
- A complete mapping from capability identifiers within that namespace to risk tiers
- Any additional state-gate predicates for Sensitive-tier capabilities

A conformant implementation MAY support zero or more profiles. Profile rules MUST
NOT override the Forbidden tier: a capability that is Forbidden under the base
classification MUST remain Forbidden regardless of any profile rule.

The automotive/VHAL profile (mapping AAOS `VehicleProperty` symbolic names to
risk tiers) is one such profile. Its contents are outside the scope of this
specification; it is documented separately.

---

## 4. Mandate Format

### 4.1 Mandate Purpose

A Mandate is a signed document issued by an Authority that grants a named
Proposer permission to invoke a specific set of capabilities within defined
boundaries. The Mandate is the sole authorization artifact that the Decision
Engine evaluates.

### 4.2 Normative Schema

A Mandate MUST contain the following sections and fields:

**`[mandate]` — Identity and validity**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_did` | string | MUST | DID of the Proposer this mandate authorizes |
| `agent_name` | string | MUST | Human-readable name of the Proposer |
| `issuer_did` | string | SHOULD | DID of the Authority that issued the mandate |
| `issued_at` | RFC3339 timestamp | SHOULD | Time of issuance |
| `expires_at` | RFC3339 timestamp | SHOULD | Time after which the mandate is invalid |
| `workspace_root` | string | OPTIONAL | Filesystem root; all path boundaries are relative to this |
| `proposal_hash` | string | OPTIONAL | SHA-256 of the governance proposal that authorized this mandate |
| `signature` | hex-encoded bytes | MUST | ed25519 signature over the canonical signing payload (§4.5) |
| `issuer_pubkey` | hex-encoded bytes | MUST | ed25519 public key of the Authority |

**`[capabilities]` — What the Proposer may do**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tools` | list of strings | MUST | Capability identifiers the Proposer is authorized to invoke |

**`[boundaries]` — Resource limits**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fs_read` | list of glob patterns | OPTIONAL | Paths the Proposer may read |
| `fs_write` | list of glob patterns | OPTIONAL | Paths the Proposer may write |
| `fs_deny` | list of glob patterns | OPTIONAL | Paths the Proposer is always denied, regardless of allow lists |
| `net_allow` | list of host patterns | OPTIONAL | Hosts the Proposer may access |
| `net_deny` | list of host patterns | OPTIONAL | Hosts always denied |
| `cmd_allow` | list of strings | OPTIONAL | Command base names the Proposer may invoke |
| `cmd_deny` | list of patterns | OPTIONAL | Command patterns always denied |

**`[jurisdiction]` — Temporal constraints**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `region` | string | OPTIONAL | Geographic or regulatory region |
| `operating_hours` | string | OPTIONAL | Allowed operating window, format `HH:MM-HH:MM` |

**`[escalation]` — Human-in-the-loop routing**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `escalate_tools` | list of strings | OPTIONAL | Capabilities requiring human approval before ALLOW |
| `escalate_to` | string | OPTIONAL | DID of the required approver |

**`[rate_limit]` — Call volume**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_calls_per_minute` | unsigned integer | OPTIONAL | Maximum calls in any 60-second window |

### 4.3 Mandate Serialization

For wire transport and storage, a Mandate MUST be representable in a
human-readable, deterministically serializable format. The reference format is
TOML. Implementations MAY support additional formats provided the canonical
signing payload (§4.5) is computed identically regardless of transport format.

### 4.4 DID Format

A2G uses the `did:a2g:` method. A DID MUST have the form:

```
did:a2g:<base58btc-encoded-ed25519-public-key>
```

The encoded portion MUST be the 32-byte little-endian representation of the
ed25519 public key, base58btc-encoded. A verifier MUST be able to derive the
public key from the DID directly, without external resolution.

### 4.5 Mandate Signing Scheme

**Algorithm:** ed25519 (RFC 8032)

**Canonical signing payload:**

```
MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>
```

Where:
- `MANDATE:` is a domain-separation prefix. This prefix ensures that a mandate
  signature cannot be valid in any other A2G signing context.
- `<capabilities_hash>` is computed as follows (all steps are normative):
  1. Collect the `[capabilities].tools` list.
  2. Sort the tool names lexicographically in ascending byte order (UTF-8 string comparison).
  3. Join with a single U+000A LINE FEED (`\n`) character. An empty list produces the empty string `""`.
  4. Compute SHA-256 over the UTF-8 encoding of the joined string.
  5. Hex-encode the digest using lowercase hex digits (64 characters).

  Changing the sort order, separator, or hash algorithm produces a different
  `capabilities_hash` and breaks all existing signatures. Implementations MUST
  follow this procedure exactly.
- Fields are joined with `:` as the delimiter. Empty optional fields are included
  as empty strings to maintain a fixed structure.

A verifier MUST reconstruct this payload from the mandate fields and verify the
ed25519 signature against `issuer_pubkey`. A verifier MUST NOT accept a mandate
whose signature does not verify.

**Domain-separation prefixes used in this protocol:**

| Prefix | Context |
|--------|---------|
| `MANDATE:` | Mandate signing payload |
| `DELEGATION:` | Authority delegation chain signing payload |
| `REVIEW:` | Governance proposal review signing payload |
| `REQUEST:` | HITL request binding hash (§7.3) |
| `APPROVAL:` | HITL approval grant signing payload (§7.4) |
| `RECEIPT:` | Gateway receipt canonical payload (§9.4) |

No signature produced under one prefix MUST be valid under a different prefix.
Implementations MUST verify that they are checking signatures with the correct
prefix for the artifact type.

### 4.6 Authority Chains

A Mandate MAY carry a delegation chain allowing sub-authorities to issue mandates
on behalf of a root Authority. A delegation MUST:

- Be signed by the delegating key with the `DELEGATION:` prefix
- Carry the grantee's DID and a scope constraint (which capabilities MAY be
  further delegated or granted)
- Have its own `expires_at`

A verifier MUST walk the chain from the mandate's `issuer_pubkey` to the known
root Authority key, verifying each link. A chain with any broken or expired link
MUST be treated as invalid.

### 4.7 Mandate Verification — Minimum Requirements

A verifier MUST check, in order:

1. The mandate is parseable and all MUST fields are present and non-empty.
2. `agent_did` is well-formed (§4.4).
3. The canonical signing payload is reconstructable from the mandate fields.
4. The ed25519 signature verifies against `issuer_pubkey`.
5. If `expires_at` is present, the current time is before `expires_at`.
6. If a delegation chain is present (§4.6), the full chain verifies.

A mandate that fails any of these checks MUST be rejected as invalid.

---

## 5. Decision Pipeline

### 5.1 Overview

The Decision Engine MUST evaluate a mandate and capability request through the
following ordered steps. The ordering is normative. A step MUST NOT be skipped,
reordered, or deferred.

Each step takes the inputs described and produces either:
- **Pass:** evaluation continues to the next step
- **Halt:** a Verdict is immediately returned; no subsequent step executes

The forbidden pre-check MUST execute before Step 0. This is not a numbered step
to distinguish it structurally: it does not consult the mandate at all.

### 5.2 Pre-check: Empty Capability Identifier

**Input:** The capability identifier string.  
**Condition:** The identifier is the empty string.  
**On fail:** DENY, `policy_rule = "invalid_request: tool name must not be empty"`.

### 5.3 Pre-check: Forbidden Domain

**Input:** The capability identifier string.  
**Condition:** `classify(capability) == Forbidden`.  
**On fail:** DENY, `policy_rule = "vehicle_forbidden_domain: '<capability>' is in the safety-critical domain and cannot be granted by any mandate"`.

This check MUST execute before signature verification and before any mandate
field is consulted. See §1.4 invariant 4 and §2.3.

### 5.4 Step 0 — Revocation

**Input:** `agent_did`, `mandate_hash`, ledger.  
**Condition:** `ledger.is_revoked(agent_did, mandate_hash)` returns true.  
**On fail:** DENY, `policy_rule = "mandate_revoked"`.

### 5.5 Step 1 — Mandate Signature

**Input:** The full mandate document.  
**Condition:** The ed25519 signature does not verify per §4.5.  
**On fail:** DENY, `policy_rule = "mandate_invalid: <reason>"`.

### 5.6 Step 2 — TTL

**Input:** `mandate.expires_at`, injected `now` timestamp.  
**Condition:** `now >= expires_at`.  
**On fail:** EXPIRED, `policy_rule = "mandate_ttl_exceeded"`.

The Decision Engine MUST use the injected `now` value, never the wall clock.

### 5.7 Step 3 — Tool Authorization

**Input:** Capability identifier, `mandate.capabilities.tools`.  
**Condition:** Identifier not in the tools list.  
**On fail:** DENY, `policy_rule = "tool_not_authorized: '<capability>' not in capabilities.tools"`.

### 5.8 Step 4 — Boundary Checks

**Input:** Request parameters, `mandate.boundaries`.  
**Condition:** Any of the following sub-checks fails.

**4a — Filesystem deny:** If the request carries a `path` parameter, and it
matches any pattern in `fs_deny`, the check MUST fail regardless of any allow
pattern. DENY wins over ALLOW.

**4b — Filesystem read:** If the capability is a read operation and `fs_read` is
non-empty, the path MUST match at least one pattern in `fs_read`.

**4c — Filesystem write:** If the capability is a write operation and `fs_write`
is non-empty, the path MUST match at least one pattern in `fs_write`.

**4d — Network:** If the request carries a `url` parameter, and the resolved
hostname matches a `net_deny` pattern that is not overridden by a `net_allow`
match, the check MUST fail.

**4e — Command:** If the request carries a `command` parameter, and the command
or its base name matches a `cmd_deny` pattern, or is not in `cmd_allow` (when
`cmd_allow` is non-empty), the check MUST fail.

**On fail:** DENY, `policy_rule = "boundary_violation: <detail>"`.

Path comparisons MUST use logical normalization (resolving `.` and `..` segments)
before matching. The Decision Engine MUST NOT call the filesystem to resolve
paths during decision evaluation. If `workspace_root` is set, path parameters
are interpreted relative to it before matching.

### 5.9 Step 4.5 — Attested State Gating

**Input:** Capability risk tier, `VerifiedVehicleState` (or absent).  
**Condition:** Risk tier is Sensitive and the verified state does not satisfy
the state gate defined by the applicable profile.

This step MUST only execute for Sensitive-domain capabilities. It MUST NOT
execute for Comfort, Convenience, or Forbidden capabilities.

The `VerifiedVehicleState` type MUST carry evidence of verification (see §6).
Raw, unverified state MUST NOT be accepted at this step. If no verified state is
provided, the fail-safe default MUST be used: a state indicating worst-case
conditions (maximum speed, active-drive gear). The fail-safe default MUST produce
DENY for all Sensitive capabilities.

**On fail:** DENY, `policy_rule = "vehicle_state_violation: <reason>"`.

### 5.10 Step 5 — Jurisdiction

**Input:** `mandate.jurisdiction.operating_hours`, injected `now`.  
**Condition:** `operating_hours` is set and current time is outside the allowed
window.  
**On fail:** DENY, `policy_rule = "jurisdiction_violation: <detail>"`.

The Decision Engine MUST use the injected `now` for this check.

### 5.11 Step 6 — Escalation

**Input:** Capability identifier, `mandate.escalation.escalate_tools`.  
**Condition:** Identifier is in `escalate_tools` and no valid approval grant has
been supplied (i.e., this is Phase 1, not Phase 2 with a validated grant).  
**On "fail":** PENDING_APPROVAL (not DENY — the Proposer may re-enter with a
grant). The Decision Engine MUST populate `Verdict.pending_approval` with a
`PendingApprovalBinding` (§7.2) before returning.

This step is bypassed in Phase 2 when an `ApprovalGrant` has been validated
(§7.5). It MUST NOT be bypassed in Phase 1.

### 5.12 Step 7 — Rate Limit

**Input:** `agent_did`, `mandate_hash`, `mandate.rate_limit.max_calls_per_minute`,
ledger.  
**Condition:** `ledger.count_recent(agent_did, mandate_hash, 60s)` exceeds the
configured limit.  
**On fail:** DENY, `policy_rule = "rate_limit_exceeded"`.

If `max_calls_per_minute` is absent or zero, this step MUST be treated as always
passing.

### 5.13 ALLOW

If all pre-checks and steps 0–7 pass, the Decision Engine MUST return ALLOW.

### 5.14 Injected-Clock Requirement

The Decision Engine MUST accept an explicit clock value (`now`) as an input
parameter. It MUST NOT read the wall clock internally. This ensures that:

- The same inputs always produce the same Verdict (reproducibility)
- Tests can drive the engine through any time scenario without system-clock
  manipulation
- A Verdict recorded in the ledger can be replayed exactly from its inputs

### 5.15 Phase 2 Pipeline

When a valid `ApprovalGrant` is supplied (`decide_with_approval()`), the pipeline
executes as follows:

1. Pre-check: Forbidden domain (§5.3). MUST execute even in Phase 2.
2. Approval grant validation: binding_id match, request_hash match, grant TTL,
   grant ed25519 signature (§7.5).
3. Pending binding TTL check: the Phase 1 PendingApprovalBinding must not be expired.
4. Steps 0–7 as specified in §5.4–§5.12, with Step 6 (escalation) bypassed.

On success, the ALLOW Verdict MUST carry `parent_receipt_hash` linking it to the
Phase 1 PENDING_APPROVAL receipt and `correlation_id` set to the `binding_id`.

---

## 6. Attested State

### 6.1 Purpose

Capabilities in the Sensitive domain depend on physical system state (e.g.,
vehicle speed and gear) to determine whether they are safe to perform. Unverified
state is a trust hole: an adversary who can inject or replay state values can
defeat the state gate entirely.

This section defines the requirements for state that the Decision Engine is
permitted to use for state gating.

### 6.2 Unverified State MUST NOT Influence Decisions

The Decision Engine MUST NOT use raw, unverified state values for Sensitive-domain
gating. A `VehicleState` value that has not been verified by the trusted enforcing
layer MUST NOT reach the Decision Engine.

The wrapper type `VerifiedVehicleState` MUST carry evidence of how the contained
state was established. This evidence MUST be recorded in the Verdict's `state_trust`
field for audit purposes.

### 6.3 State Trust Levels

| Level | String value | Meaning |
|-------|-------------|---------|
| Attested | `"attested"` | State was cryptographically verified (signature + freshness); provided by a trusted ECU or sensor via the Enforcing Gateway |
| Operator-trusted | `"operator_trusted"` | State was supplied by an operator who accepted responsibility; no cryptographic verification was performed |
| None | `"none"` | No state was provided; fail-safe default was used |

The Enforcing Gateway MUST only accept `"attested"` trust level as sufficient for
a Sensitive-domain action to proceed with bus write. `"operator_trusted"` MAY be
used by the Decision Engine during a pre-production interim phase but MUST be
clearly labeled in the receipt.

### 6.4 Attestation Requirements

A state value with trust level `"attested"` MUST satisfy all of the following:

1. **Signature:** The state MUST carry an ed25519 signature from a known,
   provisioned ECU or HAL signing key over the state fields.
2. **Freshness:** The state MUST carry a monotonic timestamp or a
   challenge-nonce issued by the verifier. The verifier MUST check that the
   timestamp is within the attestation freshness window, or that the nonce
   matches a challenge it issued.
3. **Both are required:** A valid signature on a stale state MUST be rejected.
   A fresh state without a valid signature MUST be rejected.

### 6.5 Attestation Freshness Window

The attestation freshness window defines the maximum age of a signed state value
that may be used for a Sensitive-domain decision.

- The default attestation freshness window is **500 milliseconds**.
- This value is **configurable** per deployment. The appropriate value depends on
  the sensor update rate and the enforcement path latency.
- The window is **unidirectional (past-only):** a state timestamp in the future
  MUST be rejected.
- The constant name for implementations is `ATTESTATION_FRESHNESS_MS`.

### 6.6 Fail-Safe Default

If no `VerifiedVehicleState` is supplied, the Decision Engine MUST use a fail-safe
default state. The fail-safe default MUST represent worst-case conditions that
cause all Sensitive-domain capabilities to produce DENY.

The reference fail-safe is: `{speed_kph: 999.0, gear: Drive, actor: Driver}`.

Omitting vehicle state for a Sensitive-domain capability MUST result in DENY, not
ALLOW.

### 6.7 Verifier Placement

State verification (signature check + freshness check) MUST be performed by the
Enforcing Gateway, not the Decision Engine. This preserves the Decision Engine's
purity: it does not hold signing keys, does not call the HAL, and does not perform
I/O. The Enforcing Gateway supplies only the verified result to the Decision Engine.

---

## 7. Two-Phase Approval

### 7.1 Overview

Human-in-the-loop (HITL) approval is modeled as a two-phase state machine. Both
phases produce pure, deterministic Decision Engine evaluations. All asynchrony
lives outside the Decision Engine.

**Phase 1:** The Decision Engine computes that escalation is required and returns
PENDING_APPROVAL immediately (bounded time, no waiting).

**Phase 2:** After a human approver produces a signed `ApprovalGrant`, the
Enforcing Gateway feeds the grant into a second Decision Engine call
(`decide_with_approval()`), which validates the grant and — if valid — runs the
full pipeline with escalation bypassed.

### 7.2 PendingApprovalBinding

When the Decision Engine returns PENDING_APPROVAL, it MUST populate
`Verdict.pending_approval` with a `PendingApprovalBinding` containing:

| Field | Type | Description |
|-------|------|-------------|
| `binding_id` | UUID v4 | Uniquely identifies this pending request |
| `request_hash` | SHA-256 hex | Binds the approval to the exact action (§7.3) |
| `escalate_to` | DID string | DID of the required approver |
| `ttl_expires_at` | RFC3339 timestamp | Deadline; Phase 2 MUST complete before this |

The default pending approval TTL is **5 minutes**. This value MAY be overridden
per deployment.

### 7.3 Request Hash

The `request_hash` binds an approval to one specific action invocation. It MUST
be computed as:

```
request_hash = SHA-256("REQUEST:" || mandate_hash || ":" || tool || ":" || params_hash || ":" || timestamp)
```

Where `"REQUEST:"` is a domain-separation prefix, `mandate_hash` is the SHA-256
of the mandate document, `params_hash` is the SHA-256 of the JSON-serialized
parameters, and `timestamp` is the RFC3339 Phase 1 evaluation time.

A grant whose `request_hash` does not match the pending binding's `request_hash`
MUST be rejected.

### 7.4 ApprovalGrant

An `ApprovalGrant` is a signed token produced by the human approver. It MUST contain:

| Field | Type | Description |
|-------|------|-------------|
| `binding_id` | string | MUST match the `PendingApprovalBinding.binding_id` |
| `request_hash` | string | MUST match the `PendingApprovalBinding.request_hash` |
| `approver_did` | string | DID of the approver |
| `approver_pubkey` | hex-encoded bytes | ed25519 public key of the approver |
| `signature` | hex-encoded bytes | ed25519 signature over the grant payload (below) |
| `expires_at` | RFC3339 timestamp | Grant TTL; grant MUST be rejected at or after this time |
| `parent_receipt_hash` | string | Receipt hash of the Phase 1 PENDING_APPROVAL receipt |

**ApprovalGrant signing payload:**

```
SHA-256("APPROVAL:" || binding_id || ":" || request_hash || ":" || expires_at)
```

The `"APPROVAL:"` prefix is a domain separator. The signature is computed over the
SHA-256 digest of this string, not the string itself.

### 7.5 Phase 2 Grant Validation

The Decision Engine MUST validate the `ApprovalGrant` against the
`PendingApprovalBinding` in the following order. Any failure MUST produce DENY:

1. `binding_id` in the grant MUST equal `binding_id` in the pending binding.
2. `request_hash` in the grant MUST equal `request_hash` in the pending binding.
3. Current time (`now`) MUST be before `grant.expires_at`.
4. The ed25519 signature MUST verify against `approver_pubkey` using the
   `"APPROVAL:"` payload.
5. Current time MUST be before `pending.ttl_expires_at`.

A grant that passes all five checks is valid. The Decision Engine proceeds with
the full pipeline (steps 0–7, escalation bypassed).

### 7.6 Forbidden is Always Denied

The Forbidden pre-check (§5.3) MUST execute in Phase 2, before grant validation.
A Forbidden capability MUST be denied even if:

- A valid `ApprovalGrant` is present
- The mandate lists the capability in `capabilities.tools`
- Verified state satisfies any conceivable state gate

There is no grant or approval token that can authorize a Forbidden capability.
This MUST be tested explicitly.

### 7.7 Ledger Chain Linking

On Phase 2 ALLOW, the Verdict MUST carry:
- `parent_receipt_hash` = `grant.parent_receipt_hash` (linking to the Phase 1 receipt)
- `correlation_id` = `pending.binding_id`

This enables an auditor to reconstruct the full causal chain: initial request →
escalation → human approval → authorization.

---

## 8. Receipt and Ledger

### 8.1 Receipt Purpose

A Receipt is the tamper-evident record that a Verdict was produced for a specific
action at a specific time. Receipts form an append-only, hash-chained ledger. An
auditor with the ledger and the engine's parameters MUST be able to reproduce any
historical Verdict and verify the integrity of the full audit trail.

### 8.2 Receipt Fields

A Receipt MUST contain:

| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | UUID v4 | Unique identifier for this receipt |
| `verdict_id` | string | From `Verdict.verdict_id`; links receipt to decision |
| `agent_did` | string | DID of the Proposer |
| `tool` | string | Capability identifier |
| `params_hash` | SHA-256 hex | Hash of the JSON-serialized request parameters |
| `decision` | string | `"ALLOW"`, `"DENY"`, `"EXPIRED"`, `"PENDING_APPROVAL"` |
| `policy_rule` | string | Human-readable reason for the verdict |
| `policy_hash` | SHA-256 hex | Hash of `policy_rule` |
| `timestamp` | RFC3339 string | Time of receipt generation |
| `prev_hash` | SHA-256 hex | Hash of the immediately preceding receipt (or genesis hash) |
| `receipt_hash` | SHA-256 hex | Hash of all fields above (chain link for next receipt) |
| `state_trust` | string | `"attested"` \| `"operator_trusted"` \| `"none"` |

The following fields are OPTIONAL but SHOULD be present for full lineage:

| Field | Description |
|-------|-------------|
| `mandate_hash` | SHA-256 of the mandate document used |
| `proposal_hash` | SHA-256 of the governance proposal, if applicable |
| `delegation_chain_hash` | SHA-256 of the delegation chain, if applicable |
| `issuer_did` | DID of the mandate issuer |
| `parent_receipt_hash` | For Phase 2 ALLOW: hash of the Phase 1 receipt |
| `correlation_id` | For Phase 2: the `binding_id` linking both phases |

### 8.3 Receipt Hash Computation

The `receipt_hash` MUST be computed as:

```
SHA-256(
  receipt_id ":" verdict_id ":" agent_did ":" tool ":" params_hash ":"
  decision ":" policy_hash ":" timestamp ":" prev_hash
  [":mandated_hash ":" proposal_hash]          -- when mandate_hash is non-empty
  [":delegation_chain_hash ":" issuer_did
    ":" authority_level ":" scope_hash]        -- when delegation_chain_hash is non-empty
  [":correlation_id ":" parent_receipt_hash]   -- when correlation_id is non-empty
  [":state_trust:" state_trust]                -- when state_trust is non-empty
)
```

The hash input is the concatenation of fields separated by `":"`. Optional
sections are appended only when the leading field is non-empty. This construction
ensures that receipts generated before optional fields existed remain verifiable:
their hash inputs simply omit those sections.

The hex-encoded SHA-256 of this concatenated string is the `receipt_hash`.

### 8.4 Hash Chain

Receipts form a hash chain. The first receipt in a chain MUST carry a `prev_hash`
equal to the 64-character genesis hash (`"0"` × 64). Each subsequent receipt's
`prev_hash` MUST equal the `receipt_hash` of the immediately preceding receipt.

An auditor verifying an audit trail MUST:

1. Verify that the first receipt's `prev_hash` is the genesis hash.
2. For each receipt, recompute `receipt_hash` from all fields and verify it
   matches the stored value.
3. For each pair of adjacent receipts, verify that `receipts[i].prev_hash ==
   receipts[i-1].receipt_hash`.

A chain that fails any of these checks MUST be reported as invalid.

### 8.5 Receipt Storage

Receipts MUST be stored in an append-only ledger. A conformant ledger MUST NOT
permit modification or deletion of stored receipts. The ledger MUST support
querying by `agent_did`, `tool`, `decision`, and time range.

The reference storage format is SQLite with `PRAGMA journal_mode=WAL` and
`PRAGMA busy_timeout=5000`. Implementations MAY use any storage backend provided
the append-only and query requirements are met.

### 8.6 Receipt Verification

A verifier with a receipt and the corresponding inputs MUST be able to:

1. Recompute `policy_hash = SHA-256(policy_rule)` and verify it matches.
2. Recompute `receipt_hash` per §8.3 and verify it matches.
3. Confirm the receipt's position in the chain using `prev_hash`.

A verifier with the original mandate, parameters, and injected clock value MUST be
able to reproduce the Verdict and confirm it matches the receipt.

---

## 9. Enforcement Contract

### 9.1 Overview

The Enforcing Gateway is the component that translates an ALLOW verdict into an
action on the protected resource. It operates independently of the Decision Engine
and MUST re-verify the receipt before acting.

The gateway's job is narrower than the Decision Engine's: it does not re-run the
full 8-step mandate evaluation. It verifies that the Decision Engine decided
correctly for this specific action, re-checks the single non-overridable invariant
(Forbidden), and performs the write.

### 9.2 Trust Domain Isolation

The Enforcing Gateway MUST operate in a trust domain that the Proposer and
Decision Engine cannot influence. The protocol contract is identical across all
isolation levels; isolation depth determines the attack surface:

| Tier | Isolation mechanism |
|------|---------------------|
| Development | Separate OS process on the same host |
| Pre-production | Hypervisor partition or hardware-enforced memory isolation |
| Production | Separate safety MCU or HSM-backed secure enclave |

### 9.3 Sole Writer Invariant

The Enforcing Gateway MUST be the sole writer to the protected resource. No path
from the Proposer, the Decision Engine, or any rich-domain component to the
protected resource MUST exist that does not pass through the Enforcing Gateway.
This is an architectural invariant, not a software policy. Conformant deployments
MUST enforce this at the hardware or operating-system isolation boundary.

### 9.4 Gateway Receipt

Before an action can be enforced, the rich domain MUST present a Gateway Receipt
to the Enforcing Gateway. A Gateway Receipt MUST contain:

| Field | Type | Description |
|-------|------|-------------|
| `verdict_id` | string | From `Verdict.verdict_id` |
| `decision` | string | MUST be `"ALLOW"` to proceed |
| `tool` | string | Capability identifier |
| `params_json` | string | Full request parameters as JSON |
| `policy_rule` | string | Verdict reason (informational) |
| `state_trust` | string | Trust level of state used in decision |
| `binding_id` | string | Phase 2 binding identifier; empty for Phase 1 actions |
| `request_hash` | string | `SHA-256(tool || params_json || issued_at_ms)` |
| `issued_at_ms` | integer | Unix milliseconds at receipt construction |
| `nonce_hex` | string | 16 random bytes, hex-encoded |
| `signature_hex` | string | ed25519 signature over the canonical payload |

**Gateway receipt canonical payload (signed):**

```
RECEIPT:<verdict_id>:<decision>:<tool>:<request_hash>:<binding_id>:<issued_at_ms>:<nonce_hex>
```

The full `params_json` is covered by `request_hash` rather than included directly
in the signed string; the gateway verifies the hash rather than the full payload.

### 9.5 Gateway Verification Steps

The Enforcing Gateway MUST perform the following checks in order. Any failure
MUST terminate the request with no bus write and no error disclosure to the rich
domain beyond "refused."

**Step 1 — Forbidden re-check**  
Apply the Forbidden classifier (§3.3) to `receipt.tool`. If the result is
Forbidden, refuse immediately. This check MUST precede signature verification and
is performed unconditionally on unverified input (the classifier is
allocation-free, panic-free, and bounded — §3.3 item 2).

**Step 2 — Signature**  
Recompute the canonical payload from receipt fields. Verify the ed25519 signature
against the known rich-domain receipt-signing public key. Reject if invalid.

**Step 3 — Decision is ALLOW**  
`receipt.decision` MUST equal `"ALLOW"`. Any other value (DENY, EXPIRED,
PENDING_APPROVAL) MUST be rejected. The gateway MUST NOT take any action on a
non-ALLOW receipt.

**Step 4 — Freshness**  
`receipt.issued_at_ms` MUST be within ±`RECEIPT_FRESHNESS_MS` milliseconds of
the gateway's current time. The check is bidirectional (past and future) to
tolerate clock skew between co-located processes. Receipts outside this window
MUST be rejected.

The default receipt freshness window is **2000 milliseconds**. This value MUST be
configurable per deployment. The constant name for implementations is
`RECEIPT_FRESHNESS_MS`.

**Step 5 — Anti-replay (nonce)**  
`receipt.nonce_hex` MUST NOT appear in the gateway's recent-nonce ring buffer.
The ring buffer MUST cover at least the freshness window duration. A nonce that
has been seen MUST be rejected even if the receipt is otherwise valid. On
acceptance, the nonce MUST be added to the ring buffer.

**Step 6 — Action match**  
The gateway MUST recompute `SHA-256(tool || params_json || issued_at_ms)` and
verify it equals `receipt.request_hash`. This confirms the receipt covers exactly
the action being presented.

**Step 7 — Binding match (Phase 2 only)**  
If `receipt.binding_id` is non-empty, the gateway MUST verify that `binding_id`
corresponds to an approved, non-expired entry in the pending-approval queue and
MUST consume (remove) the entry. A binding that is absent, expired, or has already
been consumed MUST be rejected.

Only after all seven checks pass MUST the gateway write to the protected resource.

### 9.6 Freshness Windows Summary

| Artifact | Constant | Default | Directionality | Purpose |
|----------|----------|---------|---------------|---------|
| ECU-signed state | `ATTESTATION_FRESHNESS_MS` | 500 ms | Unidirectional (past only) | State must not be stale sensor data |
| Gateway receipt | `RECEIPT_FRESHNESS_MS` | 2 000 ms | Bidirectional (±) | Tolerate cross-process clock skew |

These two constants govern different trust concerns and MUST NOT be substituted
for each other.

### 9.7 Pending-Approval Queue

The Enforcing Gateway MUST own the pending-approval queue. The queue maps
`binding_id` to `(SignedBinding, approval_status, ttl_expires_at)`.

Operations:
- **SignBinding:** The gateway signs a `PendingApprovalBinding` presented by the
  rich domain, stores the entry, and returns the signed blob.
- **SubmitGrant:** The gateway verifies a signed `ApprovalGrant` and marks the
  corresponding entry as approved. The gateway MUST verify the operator's
  signature against a known operator public key.
- **Consume:** When a Phase 2 receipt passes verification (step 7), the queue
  entry is consumed (one-use). A binding entry MUST NOT be consumable more than once.
- **Expiry:** Entries that have not been approved and consumed before
  `ttl_expires_at` MUST be removed. A subsequent Phase 2 attempt for an expired
  binding MUST return EXPIRED.

The rich domain MUST NOT have direct read or write access to the pending queue.

### 9.8 Gateway Key Ownership

The Enforcing Gateway MUST own:

- **Receipt-signing key:** The private key used to sign receipts in the gateway
  protocol. The corresponding verifying key is distributed to the rich domain for
  receipt construction. The gateway holds the signing key only; private key
  material MUST NOT leave the gateway's trust domain.
- **Binding-signing key:** The private key used to sign `PendingApprovalBinding`
  blobs in the HITL flow. The rich domain receives the signed blob opaquely and
  cannot manufacture a valid binding without the gateway's signing key.
- **Operator verifying key(s):** The public keys of human approvers whose
  `ApprovalGrant` signatures the gateway will accept.
- **ECU/HAL attestation verifying key(s):** The public keys of trusted state
  sources, for verifying `AttestedVehicleState` blobs.

---

## 10. Conformance

### 10.1 Conformance Levels

This specification defines three conformance levels:

**Level 1 — Decision-Conformant**  
An implementation is Decision-conformant if it correctly implements the Decision
Engine (§5), the Mandate format and verification (§4), the Verdict semantics (§2),
the Receipt format (§8), and the Capability addressing scheme (§3).

A Decision-conformant implementation MUST:
- Produce identical Verdicts to the reference implementation given the same inputs
- Implement the Forbidden pre-check as specified (before Step 0, non-overridable)
- Accept only mandates that pass the signature check (§4.7)
- Record a signed Receipt for every Verdict
- Maintain a hash-chained ledger of Receipts

**Level 2 — Gateway-Conformant**  
An implementation is Gateway-conformant if it correctly implements the Enforcing
Gateway (§9), the Two-Phase Approval flow (§7), and the Attested State contract (§6),
in addition to all Level 1 requirements.

A Gateway-conformant implementation MUST additionally:
- Operate in a separate trust domain from the Decision Engine
- Be the sole writer to the protected resource
- Perform all seven gateway verification steps (§9.5) in the specified order
- Own the pending-approval queue (§9.7)
- Own the binding-signing and receipt-signing keys (§9.8)
- Verify attested state before supplying it to the Decision Engine (§6.4)

**Level 3 — Full-Conformant**  
An implementation is Full-conformant if it satisfies Levels 1 and 2, and additionally:
- Implements the two freshness windows with the correct directionality (§9.6)
- Implements anti-replay protection using the nonce ring buffer (§9.5 Step 5)
- Implements authority delegation chains (§4.6)
- Correctly implements Phase 2 with `parent_receipt_hash` chain linking (§7.7)
- Refuses to start in production mode without a properly provisioned key store

### 10.2 Minimum Implementations

| Conformance Level | Decision Engine | Gateway | Ledger | HITL |
|-------------------|-----------------|---------|--------|------|
| Level 1 | MUST | — | MUST | OPTIONAL |
| Level 2 | MUST | MUST | MUST | MUST |
| Level 3 | MUST | MUST | MUST | MUST |

### 10.3 Conformance Test Suite

A conformance test suite is forthcoming. It will include:

- Forbidden non-overridability tests (Forbidden with valid signature, valid grant, etc.)
- Decision pipeline ordering tests (step sequence, halt-at-first-failure)
- Receipt chain integrity tests (hash verification, chain linkage)
- Gateway verification step tests (each of the seven steps, in order)
- Two-phase approval tests (binding match, hash mismatch, expired grant, expired binding)
- Freshness window tests (attestation and receipt, directionality)
- Anti-replay tests (nonce re-use, freshness boundary)

Until the formal suite is published, implementations SHOULD use the reference
implementation's test suite as a proxy.

---

## 11. Security Considerations

### 11.1 Key Custody

**Current status:** In the demo tier, the binding-signing key lives in the rich
domain process (in-process ephemeral key). This is an explicitly interim arrangement
labeled "DEMO ONLY." In this configuration, the process that requests an action
holds the key that signs the binding — a circular trust assumption.

**Normative requirement:** In a production deployment, the binding-signing key
MUST reside in the Enforcing Gateway (§9.8). The rich domain MUST hold only the
gateway's verifying key. Moving the signing key into the rich domain reduces the
enforcement boundary to an advisory verdict only, which is insufficient for
production.

### 11.2 Time-of-Check / Time-of-Use (TOCTOU)

Vehicle state is sampled at the time of decision. The physical state may change
between the decision and the action. The freshness window for attested state
(§6.5) bounds the maximum staleness of the state used in a decision, but does not
eliminate the TOCTOU window.

Deployments MUST ensure the attestation freshness window is shorter than the
minimum time in which a safety-relevant state transition could occur (e.g., a
vehicle decelerating from moving to parked). A 500 ms default window assumes the
enforcement path from decision to bus write takes at most 500 ms.

### 11.3 Executor Mismatch

A Gateway Receipt contains the capability identifier and parameters, but does not
describe the physical executor (which ECU, which actuator). If a vehicle has
multiple instances of a capability (e.g., four independent door-lock actuators),
the gateway's action match check (§9.5 Step 6) confirms the receipt covers the
correct logical action but does not verify which physical executor the action targets.

Deployments with multiple physical actuators for the same logical capability MUST
encode the specific executor in the capability identifier or parameters, ensuring
the gateway can confirm the physical target.

### 11.4 Sandbox vs. Policy

Boundary checks (§5.8) evaluate parameters using glob patterns. A policy that
permits access to `/data/**` will allow any path under `/data/`, including paths
the operator did not intend. This is a policy authoring concern, not a protocol
defect, but implementors MUST document that:

- Path normalization is logical (resolving `.` and `..` segments) and does not
  follow symlinks within `decide()`
- Symlink resolution, if needed for physical enforcement, MUST happen in the
  `enforce()` wrapper before `decide()` is called, not inside the Decision Engine

A conformant implementation MUST NOT call the filesystem during `decide()`. Symlink-based
boundary escapes are possible if the physical path has not been resolved before
the mandate is evaluated.

### 11.5 Compromised Gateway

The Enforcing Gateway is a full-bypass point: an attacker with gateway-level
access can write to the bus without any receipt. The protocol's security properties
depend on the gateway's own integrity.

- In the demo tier (same-OS process isolation), a root-level compromise defeats
  the isolation. This is known and acceptable for testing purposes.
- Production deployments MUST use the hypervisor-partition or separate-MCU tier.
  At that level, the gateway's attack surface is hardware-constrained and
  inaccessible to the rich domain even at root privilege.

### 11.6 Pending Queue Persistence

In the reference implementation, the pending-approval queue is in-memory. A
gateway restart drops all pending bindings. This is acceptable in the demo tier
but MUST be addressed in production: pending bindings for safety-critical actions
that survive a gateway restart represent un-audited pending authorizations.

Production deployments requiring durability MUST use persistent queue storage
with append-only semantics.

### 11.7 Forbidden List Governance

The Forbidden capability list is currently hardcoded in the classifier function.
This is intentional: a hardcoded list cannot be modified at runtime via a config
file, database entry, or mandate field. Any change to the Forbidden list requires
a recompile and a code review.

If a data-driven Forbidden list is introduced (e.g., for multi-OEM deployments),
the list MUST be treated as a security-sensitive signing input: it MUST carry a
governance signature, its provenance MUST be verifiable at runtime, and a
compromised signing key for the list represents a full bypass of the Forbidden
invariant.

---

## 12. References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels"
- [RFC 8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)"
- [ADR-0004] Pure Decision Path — deterministic decide() with injected clock
- [ADR-0005] Vehicle Capability Model — four-domain taxonomy, forbidden hard-deny, state gating
- [ADR-0006] AAOS VHAL Naming Layer — automotive profile
- [ADR-0007] Attested Vehicle State — cryptographic state verification requirements
- [ADR-0008] Human-in-the-Loop as a Two-Phase State Machine
- [ADR-0009] FFI C-ABI — binding integrity and interim key custody
- [ADR-0010] Enforcing Gateway — separate trust domain, wire protocol, forbidden-first

ADRs are design rationale documents, not normative sources. Where an ADR and this
specification conflict, this specification is authoritative.

---

## Appendix A — Implementation Status

This appendix records known divergences between the normative requirements of this
specification and the current reference implementation. These divergences do not
weaken the normative text; they identify work needed to achieve full conformance.

### A.1 Binding-Signing Key in the Rich Domain (Demo Tier)

**Normative (§9.8, §11.1):** The binding-signing key MUST reside in the Enforcing
Gateway.

**Current implementation status:** In the demo tier, the binding-signing key is
an ephemeral `OnceLock<SigningKey>` in the FFI layer (`a2g-ffi`), living in the
rich domain. This is labeled "DEMO ONLY" in the code and is sufficient for
end-to-end demonstration of the protocol. It is not suitable for production.

**Impact:** Level 2 and Level 3 conformance requires moving the binding-signing
key into the gateway. The gateway implementation (`a2g-gateway`) is the intended
home for this key; the migration is planned as a follow-on.

### A.2 Operator Identity Infrastructure

**Normative (§9.7):** The gateway MUST verify the operator's `ApprovalGrant`
signature against a known operator public key.

**Current implementation status:** The demo gateway uses a demo-generated operator
key pair with no key infrastructure, revocation support, or certificate hierarchy.
This is sufficient for demonstrating the protocol. Production deployment requires
a defined operator PKI.

### A.3 Pending Queue Persistence

**Normative (§11.6):** Production deployments requiring durability MUST use
persistent queue storage.

**Current implementation status:** The gateway's pending queue is in-memory only.
Queue entries are lost on gateway restart. This is acceptable for the demo tier.

### A.4 Receipt Freshness Window Directionality

**Normative (§9.6):** The receipt freshness check is bidirectional (±2000 ms).

**Current implementation status:** Implemented as specified. The attested-state
freshness check (500 ms, unidirectional) is also implemented as specified.

### A.5 Wire Transport

**Normative (§9.4):** This specification does not mandate a specific wire format.

**Current implementation status:** The demo uses newline-delimited JSON over Unix
domain sockets (`/run/a2g-gateway.sock`). A future ADR will specify a
production-appropriate transport (e.g., CBOR over CAN-TP for in-vehicle deployment).

---

## Appendix B — Design Rationale Cross-References

| Section | ADR | Topic |
|---------|-----|-------|
| §1.4 — Core invariants | ADR-0004 | Pure decide(), injected clock |
| §2.3 — Forbidden non-overridable | ADR-0005 | Hard-deny before mandate evaluation |
| §3.2 — Risk-tier model | ADR-0005 | Four-domain taxonomy |
| §4.5 — Mandate signing | ADR-0004 | Domain-separation prefixes |
| §4.6 — Authority chains | ADR-0001 | Core/CLI split; authority model |
| §5.3 — Forbidden pre-check | ADR-0005, ADR-0010 | Pre-check ordering |
| §5.9 — State gating | ADR-0005, ADR-0007 | Sensitive domain, fail-safe default |
| §6 — Attested state | ADR-0007 | State verification requirements |
| §7 — Two-phase approval | ADR-0008 | HITL state machine |
| §8 — Receipt and ledger | ADR-0004 | Receipt format, hash chain |
| §9 — Enforcement contract | ADR-0010 | Gateway trust domain, verification steps |
| §9.6 — Freshness windows | ADR-0010 §Freshness Windows | Two distinct windows, different semantics |
| §9.8 — Key ownership | ADR-0009, ADR-0010 | Binding key migration |
| §11 — Security considerations | ADR-0010 §Residual Limitations | TOCTOU, gateway compromise, key custody |
