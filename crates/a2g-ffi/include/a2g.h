#ifndef A2G_H
#define A2G_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Governance decision returned by `a2g_decide` and `a2g_decide_with_approval`.
//
// Variant mapping is stable — do NOT reorder (ADR-0009 §ABI stability).
// `ESCALATE` is intentionally absent; use `PENDING_APPROVAL` + Phase 2 API.
enum A2gDecision {
    A2G_DECISION_ALLOW = 0,
    A2G_DECISION_DENY = 1,
    // Maps to `Decision::Expired` in a2g-core: the mandate TTL has elapsed.
    A2G_DECISION_EXPIRED = 2,
    A2G_DECISION_PENDING_APPROVAL = 3,
    // Returned when a2g-ffi catches a panic, receives invalid input, or detects
    // a tampered binding MAC.
    A2G_DECISION_ERROR = -1,
};
typedef int32_t A2gDecision;

// Opaque handle holding a `Verdict` returned by a decision function.
//
// Obtain via `a2g_decide` or `a2g_decide_with_approval`.
// Release with `a2g_verdict_free`. Never dereference directly from C.
typedef struct A2gVerdictHandle A2gVerdictHandle;

// Opaque handle wrapping an operator-trusted `VerifiedVehicleState`.
//
// Obtain via `a2g_verified_state_operator_trusted`.
// Release with `a2g_verified_state_free`. Never dereference directly from C.
typedef struct A2gVerifiedStateHandle A2gVerifiedStateHandle;

// Evaluate a governance decision (Phase 1).
//
// # Parameters
// - `mandate_toml` — NUL-terminated TOML mandate string (UTF-8).
// - `tool`         — NUL-terminated tool name (UTF-8).
// - `params_json`  — NUL-terminated JSON object of tool parameters (UTF-8).
//   Pass `"{}"` for no parameters.
// - `state`        — Optional verified vehicle state handle, or NULL.
//   NULL triggers the fail-safe default (denies Sensitive tools).
//
// # Returns
// An `A2gDecision` integer. On `A2G_DECISION_PENDING_APPROVAL` the binding is
// accessible via `a2g_verdict_binding_json` on the handle written to `*out_verdict`.
// The binding JSON is MAC-protected — pass it unmodified to `a2g_decide_with_approval`.
//
// `*out_verdict` is always written on return (never NULL). Free with `a2g_verdict_free`.
//
// # Safety
// All pointer parameters must be valid NUL-terminated UTF-8 strings or NULL (for `state`).
// `out_verdict` must be a valid non-null writable pointer.
A2gDecision a2g_decide(const char *mandate_toml,
                       const char *tool,
                       const char *params_json,
                       const struct A2gVerifiedStateHandle *state,
                       struct A2gVerdictHandle **out_verdict);

// Evaluate a governance decision with a pre-validated human approval (Phase 2).
//
// # Parameters
// - `mandate_toml`  — same mandate used in Phase 1.
// - `tool`          — same tool used in Phase 1.
// - `params_json`   — same parameters used in Phase 1.
// - `state`         — same vehicle state handle used in Phase 1, or NULL.
// - `binding_json`  — MAC-protected binding JSON from Phase 1.
//   Obtain with `a2g_verdict_binding_json`. **Do not modify** — any field
//   change invalidates the MAC and returns `A2G_DECISION_ERROR`.
// - `grant_json`    — JSON-serialised `ApprovalGrant` from the human approver.
//
// # Returns
// `A2G_DECISION_ALLOW` on success; `A2G_DECISION_DENY` on policy failure;
// `A2G_DECISION_ERROR` on tampered binding, invalid JSON, or internal error.
// `*out_verdict` is always written. Free with `a2g_verdict_free`.
//
// # Safety
// Same requirements as `a2g_decide`.
A2gDecision a2g_decide_with_approval(const char *mandate_toml,
                                     const char *tool,
                                     const char *params_json,
                                     const struct A2gVerifiedStateHandle *state,
                                     const char *binding_json,
                                     const char *grant_json,
                                     struct A2gVerdictHandle **out_verdict);

// Returns the `A2gDecision` stored in the handle.
//
// # Safety
// `handle` must be a valid non-freed pointer obtained from `a2g_decide` or
// `a2g_decide_with_approval`.
A2gDecision a2g_verdict_decision(const struct A2gVerdictHandle *handle);

// Returns the verdict ID as a NUL-terminated UTF-8 string.
//
// The pointer is valid until `a2g_verdict_free` is called on the handle.
// Do NOT free this pointer separately.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_id(const struct A2gVerdictHandle *handle);

// Returns the agent DID as a NUL-terminated UTF-8 string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_agent_did(const struct A2gVerdictHandle *handle);

// Returns the tool name as a NUL-terminated UTF-8 string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_tool(const struct A2gVerdictHandle *handle);

// Returns the policy rule that determined this decision, as a NUL-terminated UTF-8 string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_policy_rule(const struct A2gVerdictHandle *handle);

// Returns the state trust basis ("attested", "operator_trusted", "none", or ""),
// as a NUL-terminated UTF-8 string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_state_trust(const struct A2gVerdictHandle *handle);

// Returns the Phase 1 binding ID when `a2g_verdict_decision` is
// `A2G_DECISION_PENDING_APPROVAL`; otherwise returns an empty string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_binding_id(const struct A2gVerdictHandle *handle);

// Returns the Phase 1 request hash when `a2g_verdict_decision` is
// `A2G_DECISION_PENDING_APPROVAL`; otherwise returns an empty string.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_request_hash(const struct A2gVerdictHandle *handle);

// Returns the Phase 1 MAC-protected binding JSON when `a2g_verdict_decision` is
// `A2G_DECISION_PENDING_APPROVAL`; otherwise empty string.
//
// Pass this value **unmodified** as `binding_json` to `a2g_decide_with_approval`.
// Any modification to the returned string will cause Phase 2 to return
// `A2G_DECISION_ERROR` (MAC mismatch). The pointer is valid until `a2g_verdict_free`.
//
// # Safety
// `handle` must be valid and non-freed.
const char *a2g_verdict_binding_json(const struct A2gVerdictHandle *handle);

// Create an operator-trusted `VerifiedVehicleState` handle.
//
// This is the **only** state-creation function in the C ABI. It is explicitly
// interim (ADR-0009 §State trust / ADR-0007 §4): the host process is asserting
// it trusts the state values. Full cryptographic attestation verification
// remains host-side and is not exposed across this ABI.
//
// # Parameters
// - `speed_kph`  — vehicle speed in km/h. Validated at this boundary: NaN, ±infinity,
//   negative, subnormal, and values above `SPEED_MAX_KPH` (1 000 km/h) are **rejected**
//   and return NULL (fail-safe DENY). Valid values are converted to mm/s internally.
// - `gear`       — gear: 0=Park, 1=Drive, 2=Reverse, 3=Neutral.
// - `actor`      — actor: 0=Driver, 1=Passenger.
//
// # Returns
// A new `A2gVerifiedStateHandle`. Free with `a2g_verified_state_free`.
// Returns NULL if `speed_kph` is invalid (NaN/inf/negative/subnormal/out-of-range),
// or if `gear` (0–3) or `actor` (0–1) values are out of range.
struct A2gVerifiedStateHandle *a2g_verified_state_operator_trusted(double speed_kph,
                                                                   int32_t gear,
                                                                   int32_t actor);

// Free an `A2gVerdictHandle` obtained from `a2g_decide` or `a2g_decide_with_approval`.
//
// After this call the pointer is invalid. Passing NULL is a no-op.
//
// # Safety
// `handle` must be either NULL or a valid non-freed pointer from a decision function.
void a2g_verdict_free(struct A2gVerdictHandle *handle);

// Free an `A2gVerifiedStateHandle` obtained from `a2g_verified_state_operator_trusted`.
//
// After this call the pointer is invalid. Passing NULL is a no-op.
//
// # Safety
// `handle` must be either NULL or a valid non-freed pointer from a state constructor.
void a2g_verified_state_free(struct A2gVerifiedStateHandle *handle);

// Return a test mandate TOML string that callers can use in smoke tests.
//
// The returned buffer must be freed with `a2g_string_free`.
// Returns NULL on allocation failure.
char *a2g_test_mandate_toml(void);

// Free a string returned by `a2g_test_mandate_toml` or other string-returning functions.
//
// Passing NULL is a no-op.
//
// # Safety
// `ptr` must be either NULL or a pointer previously returned by an a2g string function.
void a2g_string_free(char *ptr);

#endif  /* A2G_H */
