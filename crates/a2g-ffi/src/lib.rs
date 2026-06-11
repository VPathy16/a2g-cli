//! A2G FFI/C-ABI layer — embeds a2g-core decision functions in host processes.
//!
//! # ABI stability
//! See ADR-0009. The ABI is intentionally minimal: opaque handles, integer enum,
//! NUL-terminated strings. No private keys cross the boundary (ADR-0009 §Key exclusion).
//! No I/O or blocking calls inside any decision function.
//!
//! # Binding integrity (ADR-0015 — gateway key custody)
//! The binding-signing key lives in the **Enforcing Gateway only** (SPEC §9.8).
//! This crate holds no binding-signing key: Phase 1 returns the *unsigned*
//! `PendingApprovalBinding` JSON, which the host must present to the gateway's
//! `SignBinding` operation. The gateway returns a signed blob (`a2g_mac` field).
//! Phase 2 (`a2g_decide_with_approval`) verifies that blob against the
//! **gateway's binding verifying key**, supplied by the host as a 32-byte
//! ed25519 public key. A C caller that modifies any binding field (including
//! `ttl_expires_at`) will produce a signature mismatch at Phase 2, which
//! returns `A2G_DECISION_ERROR`. Passing NULL for the verifying key is also
//! `A2G_DECISION_ERROR` — fail-explicit, consistent with ADR-0014's trust
//! anchor contract.
//!
//! # Buffer ownership
//! Strings returned by accessor functions are heap-allocated by Rust and must be
//! freed with `a2g_string_free`. Passing a pointer obtained from one call to a
//! different free function is undefined behaviour.
//!
//! # Thread safety
//! Each `A2gVerdictHandle` is independently owned; concurrent calls on different
//! handles are safe. `a2g_verified_state_operator_trusted` is also thread-safe.
//! Do not share a single handle across threads without external synchronisation.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic;

use a2g_core::enforce::{decide, decide_with_approval, Decision, Verdict};
use a2g_core::hitl::{ApprovalGrant, SignedBinding};
use a2g_core::ledger::NoopLedger;
use a2g_core::vehicle::{Gear, VehicleState, VerifiedVehicleState};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

// ── Decision enum (repr(C)) ───────────────────────────────────────────────────

/// Governance decision returned by `a2g_decide` and `a2g_decide_with_approval`.
///
/// Variant mapping is stable — do NOT reorder (ADR-0009 §ABI stability).
/// `ESCALATE` is intentionally absent; use `PENDING_APPROVAL` + Phase 2 API.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2gDecision {
    Allow = 0,
    Deny = 1,
    /// Maps to `Decision::Expired` in a2g-core: the mandate TTL has elapsed.
    Expired = 2,
    PendingApproval = 3,
    /// Returned when a2g-ffi catches a panic, receives invalid input, or detects
    /// a tampered binding MAC.
    Error = -1,
}

impl From<&Decision> for A2gDecision {
    fn from(d: &Decision) -> Self {
        match d {
            Decision::Allow => A2gDecision::Allow,
            Decision::Deny => A2gDecision::Deny,
            Decision::Expired => A2gDecision::Expired,
            Decision::PendingApproval => A2gDecision::PendingApproval,
        }
    }
}

// ── Opaque handles ────────────────────────────────────────────────────────────

/// Opaque handle holding a `Verdict` returned by a decision function.
///
/// Obtain via `a2g_decide` or `a2g_decide_with_approval`.
/// Release with `a2g_verdict_free`. Never dereference directly from C.
pub struct A2gVerdictHandle {
    verdict: Verdict,
    // Cached CStrings so accessors return stable pointers within handle lifetime.
    verdict_id: CString,
    agent_did: CString,
    tool: CString,
    policy_rule: CString,
    state_trust: CString,
    binding_id: CString,
    request_hash: CString,
    /// Unsigned `PendingApprovalBinding` JSON; non-empty only when PendingApproval.
    /// The host must present this to the gateway's SignBinding operation
    /// (ADR-0015) — this crate holds no binding-signing key.
    binding_json: CString,
}

impl A2gVerdictHandle {
    fn new(v: Verdict) -> Box<Self> {
        let (binding_id, request_hash, binding_json) = match &v.pending_approval {
            Some(p) => {
                let json = serde_json::to_string(p).unwrap_or_default();
                (p.binding_id.clone(), p.request_hash.clone(), json)
            }
            None => (String::new(), String::new(), String::new()),
        };
        Box::new(A2gVerdictHandle {
            verdict_id: safe_cstring(&v.verdict_id),
            agent_did: safe_cstring(&v.agent_did),
            tool: safe_cstring(&v.tool),
            policy_rule: safe_cstring(&v.policy_rule),
            state_trust: safe_cstring(&v.state_trust),
            binding_id: safe_cstring(&binding_id),
            request_hash: safe_cstring(&request_hash),
            binding_json: safe_cstring(&binding_json),
            verdict: v,
        })
    }
}

/// Opaque handle wrapping an operator-trusted `VerifiedVehicleState`.
///
/// Obtain via `a2g_verified_state_operator_trusted`.
/// Release with `a2g_verified_state_free`. Never dereference directly from C.
pub struct A2gVerifiedStateHandle {
    state: VerifiedVehicleState,
}

// ── Trust anchor (ADR-0014) ───────────────────────────────────────────────────

/// Owned representation of the trust anchor for FFI callers.
enum TrustAnchorOwned {
    SelfSovereign,
    Roots(Vec<[u8; 32]>),
}

/// Opaque handle declaring which mandate issuers are accepted.
///
/// Obtain via `a2g_trust_anchor_self_sovereign` or `a2g_trust_anchor_roots`.
/// Release with `a2g_trust_anchor_free`. Never dereference directly from C.
///
/// Passing NULL for the trust parameter to `a2g_decide` or
/// `a2g_decide_with_approval` returns `A2G_DECISION_ERROR` immediately —
/// there is no implicit default trust mode (fail-explicit, ADR-0014).
pub struct A2gTrustAnchorHandle {
    mode: TrustAnchorOwned,
}

impl A2gTrustAnchorHandle {
    fn as_trust_anchor(&self) -> a2g_core::enforce::TrustAnchor<'_> {
        match &self.mode {
            TrustAnchorOwned::SelfSovereign => a2g_core::enforce::TrustAnchor::SelfSovereign,
            TrustAnchorOwned::Roots(keys) => a2g_core::enforce::TrustAnchor::Roots(keys),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn safe_cstring(s: &str) -> CString {
    // Replace interior NULs so the CString is always valid.
    let sanitized = s.replace('\0', "");
    CString::new(sanitized).unwrap_or_else(|_| CString::new("").unwrap())
}

/// Read a `*const c_char` as a `&str`. Returns `None` on null or invalid UTF-8.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

fn make_error_verdict() -> Box<A2gVerdictHandle> {
    let v = Verdict {
        verdict_id: String::new(),
        agent_did: String::new(),
        agent_name: String::new(),
        tool: String::new(),
        params_hash: String::new(),
        decision: Decision::Deny,
        policy_rule: "ffi_error".to_string(),
        evaluated_at: Utc::now(),
        mandate_hash: String::new(),
        proposal_hash: String::new(),
        delegation_chain_hash: String::new(),
        issuer_did: String::new(),
        authority_level: String::new(),
        scope_hash: String::new(),
        correlation_id: String::new(),
        parent_receipt_hash: String::new(),
        pending_approval: None,
        state_trust: String::new(),
    };
    A2gVerdictHandle::new(v)
}

// ── Trust anchor constructors (ADR-0014) ──────────────────────────────────────

/// Create a `SelfSovereign` trust anchor: accepts any self-consistent mandate.
///
/// Use only when issuer trust is explicitly waived (e.g. local testing).
/// This is an explicit opt-in — NOT the default. Passing NULL to `a2g_decide`
/// returns `A2G_DECISION_ERROR`; this function is the deliberate alternative.
///
/// Returns a heap-allocated handle. Free with `a2g_trust_anchor_free`.
///
/// # Safety
/// The returned pointer is always non-NULL. Free with `a2g_trust_anchor_free`.
#[no_mangle]
pub extern "C" fn a2g_trust_anchor_self_sovereign() -> *mut A2gTrustAnchorHandle {
    Box::into_raw(Box::new(A2gTrustAnchorHandle {
        mode: TrustAnchorOwned::SelfSovereign,
    }))
}

/// Create a `Roots` trust anchor: mandate's `issuer_pubkey` must match one of the
/// supplied 32-byte ed25519 public keys.
///
/// - `pubkeys_flat` — Pointer to `count * 32` contiguous bytes of ed25519 pubkeys.
/// - `count`        — Number of 32-byte keys in `pubkeys_flat`.
///
/// Returns a heap-allocated handle, or NULL if `pubkeys_flat` is NULL or `count` is 0.
/// Free with `a2g_trust_anchor_free`.
///
/// # Safety
/// `pubkeys_flat` must be valid for `count * 32` bytes and must not be NULL when `count > 0`.
#[no_mangle]
pub unsafe extern "C" fn a2g_trust_anchor_roots(
    pubkeys_flat: *const u8,
    count: usize,
) -> *mut A2gTrustAnchorHandle {
    if pubkeys_flat.is_null() || count == 0 {
        return std::ptr::null_mut();
    }
    let bytes = std::slice::from_raw_parts(pubkeys_flat, count.saturating_mul(32));
    let roots: Vec<[u8; 32]> = bytes
        .chunks_exact(32)
        .filter_map(|c| c.try_into().ok())
        .collect();
    if roots.is_empty() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(A2gTrustAnchorHandle {
        mode: TrustAnchorOwned::Roots(roots),
    }))
}

/// Release a trust anchor handle previously obtained from `a2g_trust_anchor_self_sovereign`
/// or `a2g_trust_anchor_roots`.
///
/// # Safety
/// `handle` must be a valid non-freed pointer obtained from one of the above functions,
/// or NULL (no-op).
#[no_mangle]
pub unsafe extern "C" fn a2g_trust_anchor_free(handle: *mut A2gTrustAnchorHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// ── Phase 1: a2g_decide ───────────────────────────────────────────────────────

/// Evaluate a governance decision (Phase 1).
///
/// # Parameters
/// - `mandate_cbor`     — Pointer to signed CBOR mandate bytes (ADR-0013).
/// - `mandate_cbor_len` — Length of the CBOR buffer in bytes.
/// - `tool`             — NUL-terminated tool name (UTF-8).
/// - `params_json`      — NUL-terminated JSON object of tool parameters (UTF-8).
///   Pass `"{}"` for no parameters.
/// - `state`            — Optional verified vehicle state handle, or NULL.
///   NULL triggers the fail-safe default (denies Sensitive tools).
/// - `trust`            — Trust anchor handle (ADR-0014). **Must not be NULL.**
///   NULL returns `A2G_DECISION_ERROR` immediately — there is no implicit default.
///   Use `a2g_trust_anchor_self_sovereign()` or `a2g_trust_anchor_roots()` to obtain
///   a handle and express your trust policy explicitly.
///
/// # Returns
/// An `A2gDecision` integer. On `A2G_DECISION_PENDING_APPROVAL` the **unsigned**
/// binding is accessible via `a2g_verdict_binding_json` on the handle written to
/// `*out_verdict`. Present it to the Enforcing Gateway's SignBinding operation;
/// the gateway returns the signed blob to pass to `a2g_decide_with_approval`
/// (ADR-0015 — this library holds no binding-signing key).
///
/// `*out_verdict` is always written on return (never NULL). Free with `a2g_verdict_free`.
///
/// # Safety
/// `mandate_cbor` must be valid for `mandate_cbor_len` bytes.
/// `tool` and `params_json` must be valid NUL-terminated UTF-8 strings.
/// `state` must be NULL or a valid non-freed handle.
/// `trust` must be a valid non-freed handle obtained from `a2g_trust_anchor_*`
///   functions, or NULL (returns `A2G_DECISION_ERROR`).
/// `out_verdict` must be a valid non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn a2g_decide(
    mandate_cbor: *const u8,
    mandate_cbor_len: usize,
    tool: *const c_char,
    params_json: *const c_char,
    state: *const A2gVerifiedStateHandle,
    trust: *const A2gTrustAnchorHandle,
    out_verdict: *mut *mut A2gVerdictHandle,
) -> A2gDecision {
    // Fail-explicit: NULL trust is a programming error, not a default.
    if trust.is_null() {
        if !out_verdict.is_null() {
            *out_verdict = Box::into_raw(make_error_verdict());
        }
        return A2gDecision::Error;
    }

    let result = panic::catch_unwind(|| {
        if mandate_cbor.is_null() {
            return None;
        }
        let mandate = std::slice::from_raw_parts(mandate_cbor, mandate_cbor_len);
        let tool_s = cstr_to_str(tool)?;
        let params_s = cstr_to_str(params_json).unwrap_or("{}");
        let params: serde_json::Value = serde_json::from_str(params_s).ok()?;

        let verified = if state.is_null() {
            None
        } else {
            Some(&(*state).state)
        };

        let trust_anchor = (*trust).as_trust_anchor();
        let now = Utc::now();
        let verdict = decide(
            mandate,
            tool_s,
            &params,
            &NoopLedger,
            now,
            verified,
            &trust_anchor,
        )
        .ok()?;
        Some(verdict)
    });

    let (decision, handle) = match result {
        Ok(Some(v)) => {
            let d = A2gDecision::from(&v.decision);
            (d, A2gVerdictHandle::new(v))
        }
        _ => (A2gDecision::Error, make_error_verdict()),
    };

    if !out_verdict.is_null() {
        *out_verdict = Box::into_raw(handle);
    }
    decision
}

// ── Phase 2: a2g_decide_with_approval ────────────────────────────────────────

/// Evaluate a governance decision with a pre-validated human approval (Phase 2).
///
/// # Parameters
/// - `mandate_cbor`        — same CBOR mandate bytes used in Phase 1.
/// - `mandate_cbor_len`    — length of the CBOR buffer in bytes.
/// - `tool`                — same tool used in Phase 1.
/// - `params_json`         — same parameters used in Phase 1.
/// - `state`               — same vehicle state handle used in Phase 1, or NULL.
/// - `signed_binding_json` — **gateway-signed** binding blob from the gateway's
///   SignBinding operation (ADR-0015). **Do not modify** — any field change
///   invalidates the gateway signature and returns `A2G_DECISION_ERROR`.
/// - `binding_pubkey`      — 32-byte ed25519 **verifying** key of the gateway's
///   binding-signing key. **Must not be NULL** — there is no in-process fallback
///   key (fail-explicit). Obtain from gateway provisioning / GetPublicKeys.
/// - `grant_json`          — JSON-serialised `ApprovalGrant` from the human approver.
/// - `trust`               — Trust anchor handle (ADR-0014). Must not be NULL.
///   Same handle used in Phase 1 is recommended.
///
/// # Returns
/// `A2G_DECISION_ALLOW` on success; `A2G_DECISION_DENY` on policy failure;
/// `A2G_DECISION_ERROR` on tampered/unsigned binding, NULL `binding_pubkey`,
/// invalid JSON, or internal error.
/// `*out_verdict` is always written. Free with `a2g_verdict_free`.
///
/// # Safety
/// Same requirements as `a2g_decide`; additionally `binding_pubkey` must be
/// NULL or valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn a2g_decide_with_approval(
    mandate_cbor: *const u8,
    mandate_cbor_len: usize,
    tool: *const c_char,
    params_json: *const c_char,
    state: *const A2gVerifiedStateHandle,
    signed_binding_json: *const c_char,
    binding_pubkey: *const u8,
    grant_json: *const c_char,
    trust: *const A2gTrustAnchorHandle,
    out_verdict: *mut *mut A2gVerdictHandle,
) -> A2gDecision {
    // Fail-explicit: NULL trust or NULL binding verifying key is a programming
    // error, not a default. The binding key custody is the gateway's (ADR-0015);
    // without its verifying key, Phase 2 cannot authenticate the binding.
    if trust.is_null() || binding_pubkey.is_null() {
        if !out_verdict.is_null() {
            *out_verdict = Box::into_raw(make_error_verdict());
        }
        return A2gDecision::Error;
    }

    let result = panic::catch_unwind(|| {
        if mandate_cbor.is_null() {
            return None;
        }
        let mandate = std::slice::from_raw_parts(mandate_cbor, mandate_cbor_len);
        let tool_s = cstr_to_str(tool)?;
        let params_s = cstr_to_str(params_json).unwrap_or("{}");
        let params: serde_json::Value = serde_json::from_str(params_s).ok()?;
        let binding_s = cstr_to_str(signed_binding_json)?;
        let grant_s = cstr_to_str(grant_json)?;

        // Gateway-signature verification: reject any binding not signed by the
        // gateway's binding key before it reaches core (ADR-0015).
        let key_bytes: [u8; 32] = std::slice::from_raw_parts(binding_pubkey, 32)
            .try_into()
            .ok()?;
        let gateway_binding_key = VerifyingKey::from_bytes(&key_bytes).ok()?;
        let pending = SignedBinding::verify_json(binding_s, &gateway_binding_key).ok()?;
        let grant: ApprovalGrant = serde_json::from_str(grant_s).ok()?;

        let verified = if state.is_null() {
            None
        } else {
            Some(&(*state).state)
        };

        let trust_anchor = (*trust).as_trust_anchor();
        let now = Utc::now();
        let verdict = decide_with_approval(
            mandate,
            tool_s,
            &params,
            &NoopLedger,
            now,
            verified,
            &pending,
            &grant,
            &trust_anchor,
        )
        .ok()?;
        Some(verdict)
    });

    let (decision, handle) = match result {
        Ok(Some(v)) => {
            let d = A2gDecision::from(&v.decision);
            (d, A2gVerdictHandle::new(v))
        }
        _ => (A2gDecision::Error, make_error_verdict()),
    };

    if !out_verdict.is_null() {
        *out_verdict = Box::into_raw(handle);
    }
    decision
}

// ── Verdict accessors ─────────────────────────────────────────────────────────

/// Returns the `A2gDecision` stored in the handle.
///
/// # Safety
/// `handle` must be a valid non-freed pointer obtained from `a2g_decide` or
/// `a2g_decide_with_approval`.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_decision(handle: *const A2gVerdictHandle) -> A2gDecision {
    if handle.is_null() {
        return A2gDecision::Error;
    }
    A2gDecision::from(&(*handle).verdict.decision)
}

/// Returns the verdict ID as a NUL-terminated UTF-8 string.
///
/// The pointer is valid until `a2g_verdict_free` is called on the handle.
/// Do NOT free this pointer separately.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_id(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).verdict_id.as_ptr()
}

/// Returns the agent DID as a NUL-terminated UTF-8 string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_agent_did(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).agent_did.as_ptr()
}

/// Returns the tool name as a NUL-terminated UTF-8 string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_tool(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).tool.as_ptr()
}

/// Returns the policy rule that determined this decision, as a NUL-terminated UTF-8 string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_policy_rule(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).policy_rule.as_ptr()
}

/// Returns the state trust basis ("attested", "operator_trusted", "none", or ""),
/// as a NUL-terminated UTF-8 string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_state_trust(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).state_trust.as_ptr()
}

/// Returns the Phase 1 binding ID when `a2g_verdict_decision` is
/// `A2G_DECISION_PENDING_APPROVAL`; otherwise returns an empty string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_binding_id(handle: *const A2gVerdictHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).binding_id.as_ptr()
}

/// Returns the Phase 1 request hash when `a2g_verdict_decision` is
/// `A2G_DECISION_PENDING_APPROVAL`; otherwise returns an empty string.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_request_hash(
    handle: *const A2gVerdictHandle,
) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).request_hash.as_ptr()
}

/// Returns the Phase 1 **unsigned** `PendingApprovalBinding` JSON when
/// `a2g_verdict_decision` is `A2G_DECISION_PENDING_APPROVAL`; otherwise empty string.
///
/// Present this value to the Enforcing Gateway's SignBinding operation. The
/// gateway validates, signs with its binding key, queues the entry, and returns
/// the signed blob — pass *that* blob (not this one) as `signed_binding_json`
/// to `a2g_decide_with_approval` (ADR-0015). The pointer is valid until
/// `a2g_verdict_free`.
///
/// # Safety
/// `handle` must be valid and non-freed.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_binding_json(
    handle: *const A2gVerdictHandle,
) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    (*handle).binding_json.as_ptr()
}

// ── Verified state ────────────────────────────────────────────────────────────

/// Create an operator-trusted `VerifiedVehicleState` handle.
///
/// This is the **only** state-creation function in the C ABI. It is explicitly
/// interim (ADR-0009 §State trust / ADR-0007 §4): the host process is asserting
/// it trusts the state values. Full cryptographic attestation verification
/// remains host-side and is not exposed across this ABI.
///
/// # Parameters
/// - `speed_kph`  — vehicle speed in km/h. Validated at this boundary: NaN, ±infinity,
///   negative, subnormal, and values above `SPEED_MAX_KPH` (1 000 km/h) are **rejected**
///   and return NULL (fail-safe DENY). Valid values are converted to mm/s internally.
/// - `gear`       — gear: 0=Park, 1=Drive, 2=Reverse, 3=Neutral.
/// - `actor`      — actor: 0=Driver, 1=Passenger.
///
/// # Returns
/// A new `A2gVerifiedStateHandle`. Free with `a2g_verified_state_free`.
/// Returns NULL if `speed_kph` is invalid (NaN/inf/negative/subnormal/out-of-range),
/// or if `gear` (0–3) or `actor` (0–1) values are out of range.
#[no_mangle]
pub extern "C" fn a2g_verified_state_operator_trusted(
    speed_kph: f64,
    gear: i32,
    actor: i32,
) -> *mut A2gVerifiedStateHandle {
    let result = panic::catch_unwind(|| {
        // Boundary: validate and convert float → fixed-point before reaching VehicleState.
        let speed_mmps = a2g_core::vehicle::speed_kph_to_mmps(speed_kph).ok()?;
        let g = match gear {
            0 => Gear::Park,
            1 => Gear::Drive,
            2 => Gear::Reverse,
            3 => Gear::Neutral,
            _ => return None,
        };
        let a = match actor {
            0 => a2g_core::vehicle::Actor::Driver,
            1 => a2g_core::vehicle::Actor::Passenger,
            _ => return None,
        };
        let state = VehicleState {
            speed_mmps,
            gear: g,
            actor: a,
        };
        Some(Box::new(A2gVerifiedStateHandle {
            state: VerifiedVehicleState::from_operator_trusted(state),
        }))
    });

    match result {
        Ok(Some(h)) => Box::into_raw(h),
        _ => std::ptr::null_mut(),
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Free an `A2gVerdictHandle` obtained from `a2g_decide` or `a2g_decide_with_approval`.
///
/// After this call the pointer is invalid. Passing NULL is a no-op.
///
/// # Safety
/// `handle` must be either NULL or a valid non-freed pointer from a decision function.
#[no_mangle]
pub unsafe extern "C" fn a2g_verdict_free(handle: *mut A2gVerdictHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Free an `A2gVerifiedStateHandle` obtained from `a2g_verified_state_operator_trusted`.
///
/// After this call the pointer is invalid. Passing NULL is a no-op.
///
/// # Safety
/// `handle` must be either NULL or a valid non-freed pointer from a state constructor.
#[no_mangle]
pub unsafe extern "C" fn a2g_verified_state_free(handle: *mut A2gVerifiedStateHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// ── Internal CBOR mandate compile helper ─────────────────────────────────────

/// Build a minimal signed CBOR mandate for testing/FFI smoke tests.
///
/// `tools` is the allow-list; `escalate_tools` triggers escalation.
/// `signing_key` is used to sign and derive `issuer_did`.
fn build_cbor_mandate_ffi(
    agent_name: &str,
    tools: &[String],
    escalate_tools: &[String],
    signing_key: &SigningKey,
    ttl_hours: u64,
) -> Option<Vec<u8>> {
    use a2g_core::cbor::{encode_canonical, CborMandate, MandateTbs};
    use a2g_core::mandate::capabilities_hash;
    use chrono::Duration;
    use minicbor::bytes::ByteVec;

    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let issuer_did = format!("did:a2g:{}", bs58::encode(&pubkey_bytes).into_string());

    let now = chrono::Utc::now();
    let ttl_i64 = i64::try_from(ttl_hours).unwrap_or(i64::MAX);
    let expires_at = now
        .checked_add_signed(Duration::hours(ttl_i64))
        .unwrap_or(now);

    let cap_hash_hex = capabilities_hash(tools);
    let cap_hash_bytes = hex::decode(&cap_hash_hex).ok()?;

    let tbs = MandateTbs {
        tag: "MANDATE".to_string(),
        agent_did: issuer_did.clone(),
        issuer_did: issuer_did.clone(),
        agent_name: agent_name.to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        proposal_hash: String::new(),
        workspace_root: String::new(),
        capabilities_hash: ByteVec::from(cap_hash_bytes),
        tools: tools.to_vec(),
        fs_read: vec![],
        fs_write: vec![],
        fs_deny: vec![],
        net_allow: vec![],
        net_deny: vec![],
        cmd_allow: vec![],
        cmd_deny: vec![],
        max_calls_per_minute: 60,
        max_file_size_bytes: 10_485_760,
        max_output_tokens: 4096,
        max_session_duration_sec: 3600,
        deny_patterns: vec![],
        redact_patterns: vec![],
        max_output_length: 50_000,
        region: String::new(),
        regulatory_framework: String::new(),
        environment: String::new(),
        classification: String::new(),
        operating_hours: String::new(),
        escalate_tools: escalate_tools.to_vec(),
        escalate_paths: vec![],
        escalate_hosts: vec![],
        escalate_to: String::new(),
    };

    let tbs_bytes = encode_canonical(&tbs).ok()?;
    let signature = signing_key.sign(&tbs_bytes);
    let sig_bytes = signature.to_bytes().to_vec();

    let envelope = CborMandate {
        tag: "MANDATE-V1".to_string(),
        tbs: ByteVec::from(tbs_bytes),
        signature: ByteVec::from(sig_bytes),
        issuer_pubkey: ByteVec::from(pubkey_bytes.to_vec()),
    };

    encode_canonical(&envelope).ok()
}

// ── Test helper ───────────────────────────────────────────────────────────────

/// Return a signed CBOR mandate for smoke-testing the FFI.
///
/// Writes the mandate CBOR bytes to `*out_cbor` (caller must free with `a2g_cbor_free`)
/// and the byte count to `*out_len`. Returns 0 on success, -1 on failure.
///
/// # Safety
/// `out_cbor` and `out_len` must be valid non-null writable pointers.
#[no_mangle]
pub unsafe extern "C" fn a2g_test_mandate_cbor(out_cbor: *mut *mut u8, out_len: *mut usize) -> i32 {
    let result = panic::catch_unwind(|| {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        build_cbor_mandate_ffi(
            "ffi-smoke-agent",
            &["read_file".to_string(), "write_file".to_string()],
            &[],
            &signing_key,
            24,
        )
    });
    match result {
        Ok(Some(bytes)) => {
            let len = bytes.len();
            let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
            *out_cbor = ptr;
            *out_len = len;
            0
        }
        _ => -1,
    }
}

/// Free CBOR bytes returned by `a2g_test_mandate_cbor`.
///
/// # Safety
/// `ptr` must be either NULL or a pointer returned by `a2g_test_mandate_cbor`, and
/// `len` must be the same length as was written to `*out_len`.
/// After this call the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn a2g_cbor_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// Free a string returned by `a2g_test_mandate_toml` or other string-returning functions.
///
/// Passing NULL is a no-op.
///
/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by an a2g string function.
#[no_mangle]
pub unsafe extern "C" fn a2g_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ── Rust-level tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe fn decide_c(
        mandate: &[u8],
        tool: &str,
        params: &str,
        state: *const A2gVerifiedStateHandle,
    ) -> (A2gDecision, *mut A2gVerdictHandle) {
        let trust = a2g_trust_anchor_self_sovereign();
        let t = CString::new(tool).unwrap();
        let p = CString::new(params).unwrap();
        let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
        let d = a2g_decide(
            mandate.as_ptr(),
            mandate.len(),
            t.as_ptr(),
            p.as_ptr(),
            state,
            trust,
            &mut out,
        );
        a2g_trust_anchor_free(trust);
        (d, out)
    }

    fn test_mandate() -> Vec<u8> {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        build_cbor_mandate_ffi(
            "ffi-test",
            &["read_file".to_string(), "write_file".to_string()],
            &[],
            &signing_key,
            24,
        )
        .unwrap()
    }

    /// Mandate with `tool` in both `tools` and `escalate_tools` — triggers PendingApproval.
    fn escalate_mandate(tool: &str) -> Vec<u8> {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        build_cbor_mandate_ffi(
            "ffi-escalate-test",
            &[tool.to_string()],
            &[tool.to_string()],
            &signing_key,
            24,
        )
        .unwrap()
    }

    #[test]
    fn test_allow_comfort_tool() {
        let mandate = test_mandate();
        unsafe {
            let (decision, handle) = decide_c(&mandate, "read_file", "{}", std::ptr::null());
            assert_eq!(decision, A2gDecision::Allow, "Comfort tool must be ALLOW");
            assert!(!handle.is_null());
            assert_eq!(a2g_verdict_decision(handle), A2gDecision::Allow);
            a2g_verdict_free(handle);
        }
    }

    #[test]
    fn test_forbidden_tool_denies() {
        let mandate = test_mandate();
        unsafe {
            let (decision, handle) = decide_c(&mandate, "delete_all_data", "{}", std::ptr::null());
            assert_eq!(decision, A2gDecision::Deny, "Forbidden tool must be DENY");
            assert!(!handle.is_null());
            a2g_verdict_free(handle);
        }
    }

    #[test]
    fn test_verified_state_operator_trusted_allow() {
        let mandate = test_mandate();
        unsafe {
            let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
            assert!(!state.is_null());
            let (decision, handle) = decide_c(&mandate, "read_file", "{}", state);
            assert_eq!(decision, A2gDecision::Allow);
            let trust = CStr::from_ptr(a2g_verdict_state_trust(handle))
                .to_str()
                .unwrap();
            assert_eq!(trust, "operator_trusted");
            a2g_verdict_free(handle);
            a2g_verified_state_free(state);
        }
    }

    #[test]
    fn test_invalid_gear_returns_null() {
        let h = a2g_verified_state_operator_trusted(0.0, 99, 0);
        assert!(h.is_null(), "out-of-range gear must return NULL");
        unsafe { a2g_verified_state_free(h) };
    }

    #[test]
    fn test_null_mandate_returns_error() {
        unsafe {
            let trust = a2g_trust_anchor_self_sovereign();
            let t = CString::new("read_file").unwrap();
            let p = CString::new("{}").unwrap();
            let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
            let d = a2g_decide(
                std::ptr::null(),
                0,
                t.as_ptr(),
                p.as_ptr(),
                std::ptr::null(),
                trust,
                &mut out,
            );
            assert_eq!(d, A2gDecision::Error);
            assert!(!out.is_null());
            a2g_verdict_free(out);
            a2g_trust_anchor_free(trust);
        }
    }

    #[test]
    fn test_null_trust_returns_error() {
        unsafe {
            let t = CString::new("read_file").unwrap();
            let p = CString::new("{}").unwrap();
            let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
            let d = a2g_decide(
                std::ptr::null(),
                0,
                t.as_ptr(),
                p.as_ptr(),
                std::ptr::null(),
                std::ptr::null(), // NULL trust → Error (fail-explicit, ADR-0014)
                &mut out,
            );
            assert_eq!(d, A2gDecision::Error, "NULL trust must return Error");
            assert!(!out.is_null());
            a2g_verdict_free(out);
        }
    }

    #[test]
    fn test_test_mandate_cbor_not_null() {
        unsafe {
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            let rc = a2g_test_mandate_cbor(&mut ptr, &mut len);
            assert_eq!(rc, 0, "a2g_test_mandate_cbor must return 0");
            assert!(!ptr.is_null(), "CBOR pointer must not be null");
            assert!(len > 0, "CBOR length must be > 0");
            a2g_cbor_free(ptr, len);
        }
    }

    // ── Binding integrity tests (ADR-0015: gateway key custody) ───────────────
    //
    // The FFI holds no binding-signing key. These tests simulate the GATEWAY's
    // role with a locally generated key pair: the test signs the Phase 1 binding
    // the way the gateway's SignBinding operation does, then hands the FFI only
    // the gateway's VERIFYING key — exactly the production arrangement.

    /// Simulated gateway: sign an unsigned Phase 1 binding JSON, returning
    /// (signed_blob_json, gateway_binding_verifying_key_bytes).
    fn gateway_sign(unsigned_binding_json: &str) -> (String, [u8; 32]) {
        let binding: a2g_core::hitl::PendingApprovalBinding =
            serde_json::from_str(unsigned_binding_json).unwrap();
        // This key plays the GATEWAY's binding key. The FFI under test never
        // sees the signing half — only the 32-byte verifying key below.
        let gw_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let signed = SignedBinding::sign(&binding, &gw_key).unwrap();
        (
            serde_json::to_string(&signed).unwrap(),
            gw_key.verifying_key().to_bytes(),
        )
    }

    /// Run Phase 2 through the C ABI with explicit binding blob + verifying key.
    unsafe fn phase2_c(
        mandate: &[u8],
        signed_binding_json: &str,
        binding_pubkey: *const u8,
        grant_json: &str,
        state: *const A2gVerifiedStateHandle,
    ) -> A2gDecision {
        let tool_c = CString::new("WINDOW_POS").unwrap();
        let params_c = CString::new("{}").unwrap();
        let binding_c = CString::new(signed_binding_json).unwrap();
        let grant_c = CString::new(grant_json).unwrap();
        let trust = a2g_trust_anchor_self_sovereign();
        let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
        let d = a2g_decide_with_approval(
            mandate.as_ptr(),
            mandate.len(),
            tool_c.as_ptr(),
            params_c.as_ptr(),
            state,
            binding_c.as_ptr(),
            binding_pubkey,
            grant_c.as_ptr(),
            trust,
            &mut out,
        );
        a2g_trust_anchor_free(trust);
        a2g_verdict_free(out);
        d
    }

    /// (a) Gateway-signed binding round-trips: Phase 1 → gateway sign → Phase 2 → Allow.
    #[test]
    fn test_binding_round_trip_phase2_succeeds() {
        let mandate = escalate_mandate("WINDOW_POS");
        // Parked, stopped — satisfies the Sensitive gate
        let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
        assert!(!state.is_null());

        unsafe {
            // Phase 1 — FFI returns the UNSIGNED binding
            let (d1, h1) = decide_c(&mandate, "WINDOW_POS", "{}", state);
            assert_eq!(
                d1,
                A2gDecision::PendingApproval,
                "escalate mandate must pend"
            );

            let unsigned_json = CStr::from_ptr(a2g_verdict_binding_json(h1))
                .to_str()
                .unwrap()
                .to_string();
            let bid = CStr::from_ptr(a2g_verdict_binding_id(h1))
                .to_str()
                .unwrap()
                .to_string();
            let rhash = CStr::from_ptr(a2g_verdict_request_hash(h1))
                .to_str()
                .unwrap()
                .to_string();
            a2g_verdict_free(h1);

            // The unsigned binding must carry no gateway signature field.
            let v: serde_json::Value = serde_json::from_str(&unsigned_json).unwrap();
            assert!(
                v.get("a2g_mac").is_none(),
                "Phase 1 binding must be unsigned — the FFI holds no binding key"
            );

            // Gateway signs (simulated)
            let (signed_json, gw_pubkey) = gateway_sign(&unsigned_json);

            // Approver grant
            let approver_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let grant = a2g_core::hitl::ApprovalGrant::new_signed(
                &bid,
                &rhash,
                "did:a2g:test-approver",
                &approver_key,
                300,
                Utc::now(),
                "",
            )
            .expect("test grant must sign");
            let grant_json = serde_json::to_string(&grant).unwrap();

            let d2 = phase2_c(
                &mandate,
                &signed_json,
                gw_pubkey.as_ptr(),
                &grant_json,
                state,
            );
            assert_eq!(
                d2,
                A2gDecision::Allow,
                "gateway-signed binding must allow in Phase 2"
            );
            a2g_verified_state_free(state);
        }
    }

    /// Helper: run Phase 1, gateway-sign the binding, return
    /// (signed_json, gateway_pubkey, mandate_cbor).
    fn phase1_signed_binding() -> (String, [u8; 32], Vec<u8>) {
        let mandate = escalate_mandate("WINDOW_POS");
        let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
        assert!(!state.is_null());
        unsafe {
            let (d, h) = decide_c(&mandate, "WINDOW_POS", "{}", state);
            assert_eq!(d, A2gDecision::PendingApproval);
            let json = CStr::from_ptr(a2g_verdict_binding_json(h))
                .to_str()
                .unwrap()
                .to_string();
            a2g_verdict_free(h);
            a2g_verified_state_free(state);
            let (signed, pubkey) = gateway_sign(&json);
            (signed, pubkey, mandate)
        }
    }

    /// (b) A signed binding with a mutated `request_hash` is rejected.
    #[test]
    fn test_tampered_request_hash_rejected() {
        let (signed_json, gw_pubkey, mandate) = phase1_signed_binding();

        // Mutate request_hash in the signed blob
        let mut v: serde_json::Value = serde_json::from_str(&signed_json).unwrap();
        v["request_hash"] =
            serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let tampered = serde_json::to_string(&v).unwrap();

        unsafe {
            let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
            // Grant doesn't matter — signature check fires first
            let d = phase2_c(&mandate, &tampered, gw_pubkey.as_ptr(), "{}", state);
            assert_eq!(
                d,
                A2gDecision::Error,
                "tampered request_hash must return Error"
            );
            a2g_verified_state_free(state);
        }
    }

    /// (c) A signed binding with an extended `ttl_expires_at` is rejected.
    #[test]
    fn test_tampered_ttl_rejected() {
        let (signed_json, gw_pubkey, mandate) = phase1_signed_binding();

        // Extend the TTL by decades — attacker trying to reuse an expired Phase 1 request
        let mut v: serde_json::Value = serde_json::from_str(&signed_json).unwrap();
        v["ttl_expires_at"] = serde_json::json!("2099-01-01T00:00:00Z");
        let tampered = serde_json::to_string(&v).unwrap();

        unsafe {
            let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
            let d = phase2_c(&mandate, &tampered, gw_pubkey.as_ptr(), "{}", state);
            assert_eq!(
                d,
                A2gDecision::Error,
                "tampered ttl_expires_at must return Error"
            );
            a2g_verified_state_free(state);
        }
    }

    /// (d) A binding signed by a key that is NOT the gateway's is rejected —
    /// the rich domain cannot mint its own bindings (ADR-0015 forge attempt).
    #[test]
    fn test_forged_binding_wrong_key_rejected() {
        let (signed_json, _gw_pubkey, mandate) = phase1_signed_binding();

        // The verifier is given a DIFFERENT key than the one that signed.
        let other_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_pubkey = other_key.verifying_key().to_bytes();

        unsafe {
            let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
            let d = phase2_c(&mandate, &signed_json, wrong_pubkey.as_ptr(), "{}", state);
            assert_eq!(
                d,
                A2gDecision::Error,
                "binding signed by a non-gateway key must return Error"
            );
            a2g_verified_state_free(state);
        }
    }

    /// (e) NULL binding_pubkey is fail-explicit: A2G_DECISION_ERROR.
    #[test]
    fn test_null_binding_pubkey_returns_error() {
        let (signed_json, _gw_pubkey, mandate) = phase1_signed_binding();
        unsafe {
            let state = a2g_verified_state_operator_trusted(0.0, 0, 0);
            let d = phase2_c(&mandate, &signed_json, std::ptr::null(), "{}", state);
            assert_eq!(
                d,
                A2gDecision::Error,
                "NULL binding_pubkey must return Error (fail-explicit)"
            );
            a2g_verified_state_free(state);
        }
    }
}
