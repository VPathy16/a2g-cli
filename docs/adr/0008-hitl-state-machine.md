# ADR-0008: Human-in-the-Loop as a Two-Phase State Machine

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `docs/adr/hitl-state-machine`

---

## Context

### The current model

Step 6 of the enforcement pipeline (ADR-0004, ADR-0005) is labelled "Escalation." When a tool call matches the mandate's `escalate_tools` list, `decide()` returns `ESCALATE`. The mandate's `escalate_to` field names the approving authority.

This is correct as far as it goes. The problem is what happens next — and what the current framing implies.

### Why HITL breaks decide()'s purity guarantee

Human-in-the-loop approval is **asynchronous**. A human must observe a prompt, reason about it, and respond. That response may arrive milliseconds later, minutes later, or not at all. It may be interrupted, cancelled, or rejected.

`decide()` is a **pure, bounded-time function** (ADR-0004). It takes inputs, runs the 8-step pipeline, and returns a verdict. It performs no I/O, makes no network calls, and waits for nothing. These are not incidental properties — they are the foundation of reproducibility, ledger replayability, and embeddability.

A `decide()` that waits for a human is no longer pure, no longer bounded, and no longer embeddable. It cannot be called from a `no_std` context. It cannot be unit-tested without mocking a human. Its "determinism" would include external, non-reproducible inputs.

### The conflation

The current Step 6 conflates two distinct computations:

1. **Computing that approval is required** — pure, instant, deterministic. Given this tool, this mandate, and this params, does the mandate say "escalate"? This is a pipeline step.

2. **Obtaining approval** — asynchronous, external, non-deterministic in time. Queue the request, display an HMI prompt, await a response, validate it. This is not a pipeline step.

Treating both as part of `decide()` — or as a single "ESCALATE" verdict that somehow resolves itself — creates an implicit expectation that the core will drive the async flow. It should not.

## Decision

**Human-in-the-loop is a two-phase state machine. Both phases produce pure, deterministic decide() evaluations. All asynchrony lives outside the core.**

### Phase 1 — Compute that approval is required

The agent's tool call is evaluated by `decide()`. Step 6 finds the tool in `escalate_tools`. `decide()` returns a `PendingApproval` verdict immediately — a pure, bounded-time computation. No waiting occurs. The receipt for Phase 1 is written to the ledger: `{decision: PendingApproval, tool: ..., params_hash: ..., binding_id: <uuid>}`.

`PendingApproval` is a new variant of `EnforcementDecision`. It carries:
- **`binding_id`** — a UUID that uniquely identifies this specific pending request.
- **`request_hash`** — a hash of the tool name, params, mandate hash, and timestamp. The approval in Phase 2 must be bound to this hash.
- **`escalate_to`** — the DID of the required approver, copied from the mandate.
- **`ttl`** — the time by which Phase 2 must complete, after which the `PendingApproval` expires and any supplied approval is rejected.

`decide()` returns. The agent's request is now parked — it may not proceed.

### Phase 2 — Obtain and evaluate approval

The **infrastructure layer** (the roadmap Secure Gateway, or an equivalent orchestration component) is responsible for:

1. **Queueing the pending request** and driving the HMI prompt to the human approver identified by `escalate_to`.
2. **Receiving the human's approval** — a signed approval token produced by the approver's identity tool (equivalent to signing a governance proposal).
3. **Feeding the approval as a new input** into a second `decide()` evaluation.

The second `decide()` call receives the original params plus the approval token. A new step — before Step 0, analogous to the forbidden-domain pre-check — validates the approval token:

- The approval's `request_hash` must match the pending request's `request_hash`. An approval for a different request is rejected.
- The approval's `binding_id` must match the `PendingApproval`'s `binding_id`. An approval cannot be applied to a different pending item.
- The approval must carry a valid ed25519 signature from the `escalate_to` DID's key.
- The approval must not be expired (its own TTL is checked against `now`).

On success, this step removes the escalation trigger for this call. Steps 1–7 run normally. `decide()` returns `ALLOW` (or `DENY` if another step fails). A second receipt is written: `{decision: Allow, bound_to_pending_id: <uuid>, approval_hash: ...}`.

The two receipts are linked in the ledger via `parent_receipt_hash`: the ALLOW receipt's `parent_receipt_hash` points to the `PendingApproval` receipt. The full causal chain — request → escalation → human approval → authorization — is reconstructible from the ledger.

### The parallel to signed proposals

This design is not novel. It mirrors the existing mandate lifecycle:

| Mandate flow | HITL flow |
|---|---|
| Agent proposes a mandate → produces a `Proposal` record | `decide()` returns `PendingApproval` → writes a pending receipt |
| Reviewer signs the proposal with their key | Human approver signs an approval token with their key |
| `a2g sign` consumes the approved proposal and produces a signed mandate | Phase 2 `decide()` consumes the approval token and produces an ALLOW receipt |
| The signed mandate is the authorization artifact | The ALLOW receipt is the authorization artifact |

In both flows, human judgment produces a signed, time-bounded artifact that is fed as input to a deterministic core. The core does not wait for the human — it evaluates the human's already-computed response.

### What lives where

| Concern | Owner |
|---|---|
| Compute that escalation is required | `decide()` — Phase 1 |
| Assign `binding_id` and `request_hash` | `decide()` — Phase 1 |
| Write the `PendingApproval` receipt | `enforce()` / gateway |
| Queue the request | Gateway orchestration |
| Display HMI prompt | Gateway / HMI component |
| Receive and validate the human's response (UI-level) | Gateway / HMI component |
| Produce a signed approval token | Approver identity tool |
| Verify the approval token, check binding, check TTL | `decide()` — Phase 2 pre-check |
| Run Steps 1–7 on the approved request | `decide()` — Phase 2 |
| Write the ALLOW receipt linked to the pending receipt | `enforce()` / gateway |
| Forward the command to VHAL (for vehicle tools) | Gateway, after Phase 2 ALLOW |

`decide()` is called **twice** — once per phase. Both calls are pure and replayable from their ledger entries.

## Consequences

### Positive

- `decide()` remains pure, bounded-time, and embeddable. No human wait, no queue, no I/O.
- Both phases are fully auditable: the ledger records the initial escalation and the final resolution, linked by `parent_receipt_hash` and `binding_id`.
- Approval tokens are bound to specific requests: a human's approval for action A cannot be replayed to authorize action B (different `request_hash`).
- Approval tokens are TTL'd: a cached approval cannot be used hours or days later (freshness check in Phase 2).
- The two-phase model is reproducible from the ledger — a security auditor can reconstruct the full chain: who escalated what, which human approved it, and what the final verdict was.
- Aligns with the existing signed-proposal pattern; no new cryptographic primitives required.

### Neutral

- The gateway's queue/HMI orchestration becomes a first-class component, not an afterthought. This is the right place for that complexity.
- `EnforcementDecision` gains a `PendingApproval` variant. Callers that match exhaustively on `EnforcementDecision` must handle the new variant.
- The second `decide()` call for Phase 2 requires a new pre-check (approval token validation). This is additive — Steps 1–7 are unchanged.

### Negative / Residuals

- Until the gateway exists, HITL is not fully operational end-to-end. The CLI can emit `ESCALATE` (current) or `PendingApproval` (new variant), but the queue, HMI prompt, and Phase 2 invocation require the gateway.
- The approval token format must be specified and implemented as a follow-on. The format should reuse the existing ed25519 signing infrastructure and the signed-proposal schema where possible.
- Timeout handling for expired `PendingApproval` items (the human never responded) must be specified in the gateway design. The ledger should record expiry events so that a pending item does not remain open indefinitely.

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| `decide()` blocks and polls for approval | Violates purity; blocks `no_std`; non-deterministic duration; non-replayable |
| Single ESCALATE verdict with external side effect | Conflates "approval required" with "approval obtained"; cannot be replayed from the ledger as a pure computation |
| Approval check outside `decide()` entirely (gateway only, no core validation) | Removes the binding check from the audited, signed path; an approval could be applied to the wrong request without detection |
| Callback / async fn in decide() | Not `no_std`-compatible; makes `decide()` depend on an async runtime |
| Store approval in the mandate | Mandates are per-agent, long-lived; approvals are per-action, short-lived; conflating them breaks the mandate TTL model |

## Open Questions

### Approval token schema

The signed approval token is described here at the level of required fields (`binding_id`, `request_hash`, approver DID, TTL, ed25519 signature). The exact serialisation format — whether it reuses the existing `Proposal` / `Review` JSON schema or is a new type — should be decided in the implementation ADR.

### Timeout and expiry events

When a `PendingApproval` item expires (TTL elapsed, no human response), the system should emit a receipt recording the expiry. Whether that receipt is written by the gateway polling a queue or by the Phase 2 `decide()` call that detects the expired TTL is an implementation question for the gateway design.

### Multi-approver escalation

The current mandate schema has a single `escalate_to` DID. Multi-approver quorums (e.g., two-of-three reviewers) are out of scope for this ADR. If required, the approval token format should be extended to carry a multi-signature proof, and the Phase 2 pre-check updated accordingly.
