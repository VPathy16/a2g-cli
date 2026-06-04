//! A2G FFI/C-ABI layer — embeds a2g-core decision functions in host processes.
//!
//! # ABI stability
//! See ADR-0009. The ABI is intentionally minimal: opaque handles, integer enum,
//! NUL-terminated strings. No private keys cross the boundary (ADR-0009 §Key exclusion).
//! No I/O or blocking calls inside any decision function.
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
use a2g_core::hitl::{ApprovalGrant, PendingApprovalBinding};
use a2g_core::ledger::NoopLedger;
use a2g_core::vehicle::{Gear, VehicleState, VerifiedVehicleState};
use chrono::Utc;

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
    Expired = 2,
    PendingApproval = 3,
    /// Returned when a2g-ffi catches a panic or receives invalid input.
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
    /// JSON-serialised `PendingApprovalBinding`; non-empty only when PendingApproval.
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

// ── Phase 1: a2g_decide ───────────────────────────────────────────────────────

/// Evaluate a governance decision (Phase 1).
///
/// # Parameters
/// - `mandate_toml` — NUL-terminated TOML mandate string (UTF-8).
/// - `tool`         — NUL-terminated tool name (UTF-8).
/// - `params_json`  — NUL-terminated JSON object of tool parameters (UTF-8).
///   Pass `"{}"` for no parameters.
/// - `state`        — Optional verified vehicle state handle, or NULL.
///   NULL triggers the fail-safe default (denies Sensitive tools).
///
/// # Returns
/// An `A2gDecision` integer. On `A2G_DECISION_PENDING_APPROVAL` the binding is
/// accessible via `a2g_verdict_binding_id` / `a2g_verdict_request_hash` on the
/// handle written to `*out_verdict`.
///
/// `*out_verdict` is always written on return (never NULL). Free with `a2g_verdict_free`.
///
/// # Safety
/// All pointer parameters must be valid NUL-terminated UTF-8 strings or NULL (for `state`).
/// `out_verdict` must be a valid non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn a2g_decide(
    mandate_toml: *const c_char,
    tool: *const c_char,
    params_json: *const c_char,
    state: *const A2gVerifiedStateHandle,
    out_verdict: *mut *mut A2gVerdictHandle,
) -> A2gDecision {
    let result = panic::catch_unwind(|| {
        let mandate = cstr_to_str(mandate_toml)?;
        let tool_s = cstr_to_str(tool)?;
        let params_s = cstr_to_str(params_json).unwrap_or("{}");
        let params: serde_json::Value = serde_json::from_str(params_s).ok()?;

        let verified = if state.is_null() {
            None
        } else {
            Some(&(*state).state)
        };

        let now = Utc::now();
        let verdict = decide(mandate, tool_s, &params, &NoopLedger, now, verified).ok()?;
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
/// - `mandate_toml`  — same mandate used in Phase 1.
/// - `tool`          — same tool used in Phase 1.
/// - `params_json`   — same parameters used in Phase 1.
/// - `state`         — same vehicle state handle used in Phase 1, or NULL.
/// - `binding_json`  — JSON-serialised `PendingApprovalBinding` from Phase 1.
///   Obtain by calling `a2g_verdict_binding_json` after Phase 1.
/// - `grant_json`    — JSON-serialised `ApprovalGrant` from the human approver.
///
/// # Returns
/// `A2G_DECISION_ALLOW` on success; `A2G_DECISION_DENY` or `A2G_DECISION_ERROR` on failure.
/// `*out_verdict` is always written. Free with `a2g_verdict_free`.
///
/// # Safety
/// Same requirements as `a2g_decide`.
#[no_mangle]
pub unsafe extern "C" fn a2g_decide_with_approval(
    mandate_toml: *const c_char,
    tool: *const c_char,
    params_json: *const c_char,
    state: *const A2gVerifiedStateHandle,
    binding_json: *const c_char,
    grant_json: *const c_char,
    out_verdict: *mut *mut A2gVerdictHandle,
) -> A2gDecision {
    let result = panic::catch_unwind(|| {
        let mandate = cstr_to_str(mandate_toml)?;
        let tool_s = cstr_to_str(tool)?;
        let params_s = cstr_to_str(params_json).unwrap_or("{}");
        let params: serde_json::Value = serde_json::from_str(params_s).ok()?;
        let binding_s = cstr_to_str(binding_json)?;
        let grant_s = cstr_to_str(grant_json)?;

        let pending: PendingApprovalBinding = serde_json::from_str(binding_s).ok()?;
        let grant: ApprovalGrant = serde_json::from_str(grant_s).ok()?;

        let verified = if state.is_null() {
            None
        } else {
            Some(&(*state).state)
        };

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

/// Returns the Phase 1 `PendingApprovalBinding` as a JSON string when
/// `a2g_verdict_decision` is `A2G_DECISION_PENDING_APPROVAL`; otherwise empty string.
///
/// Pass this value as `binding_json` to `a2g_decide_with_approval` in Phase 2.
/// The pointer is valid until `a2g_verdict_free` is called.
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
/// - `speed_kph`  — vehicle speed in km/h (must be ≥ 0).
/// - `gear`       — gear: 0=Park, 1=Drive, 2=Reverse, 3=Neutral.
/// - `actor`      — actor: 0=Driver, 1=Passenger.
///
/// # Returns
/// A new `A2gVerifiedStateHandle`. Free with `a2g_verified_state_free`.
/// Returns NULL if `gear` or `actor` values are out of range (gear: 0–3, actor: 0–1).
#[no_mangle]
pub extern "C" fn a2g_verified_state_operator_trusted(
    speed_kph: f64,
    gear: i32,
    actor: i32,
) -> *mut A2gVerifiedStateHandle {
    let result = panic::catch_unwind(|| {
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
            speed_kph,
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

// ── Test helper ───────────────────────────────────────────────────────────────

/// Return a test mandate TOML string that callers can use in smoke tests.
///
/// The returned buffer must be freed with `a2g_string_free`.
/// Returns NULL on allocation failure.
#[no_mangle]
pub extern "C" fn a2g_test_mandate_toml() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (did, _, _) = a2g_core::identity::generate_agent_keypair();
        let (_, secret, _) = a2g_core::identity::generate_agent_keypair();
        let template = a2g_core::mandate::generate_template("ffi-smoke-agent", &did);
        a2g_core::mandate::sign_mandate(&template, &secret, 24).ok()
    });
    match result {
        Ok(Some(s)) => match CString::new(s) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
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
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe fn decide_c(
        mandate: &str,
        tool: &str,
        params: &str,
        state: *const A2gVerifiedStateHandle,
    ) -> (A2gDecision, *mut A2gVerdictHandle) {
        let m = CString::new(mandate).unwrap();
        let t = CString::new(tool).unwrap();
        let p = CString::new(params).unwrap();
        let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
        let d = a2g_decide(m.as_ptr(), t.as_ptr(), p.as_ptr(), state, &mut out);
        (d, out)
    }

    fn test_mandate() -> String {
        let (did, _, _) = a2g_core::identity::generate_agent_keypair();
        let (_, secret, _) = a2g_core::identity::generate_agent_keypair();
        let template = a2g_core::mandate::generate_template("ffi-test", &did);
        a2g_core::mandate::sign_mandate(&template, &secret, 24).unwrap()
    }

    #[test]
    fn test_allow_comfort_tool() {
        let mandate = test_mandate();
        // read_file is in the default Comfort domain — no vehicle state needed.
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
        // delete_all_data is Forbidden in the default policy.
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
            // Parked, driver — operator trusted
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
        // safe to call free on null
        unsafe { a2g_verified_state_free(h) };
    }

    #[test]
    fn test_null_mandate_returns_error() {
        unsafe {
            let t = CString::new("read_file").unwrap();
            let p = CString::new("{}").unwrap();
            let mut out: *mut A2gVerdictHandle = std::ptr::null_mut();
            let d = a2g_decide(
                std::ptr::null(),
                t.as_ptr(),
                p.as_ptr(),
                std::ptr::null(),
                &mut out,
            );
            assert_eq!(d, A2gDecision::Error);
            assert!(!out.is_null());
            a2g_verdict_free(out);
        }
    }

    #[test]
    fn test_test_mandate_toml_not_null() {
        unsafe {
            let ptr = a2g_test_mandate_toml();
            assert!(!ptr.is_null());
            // Must be valid UTF-8 TOML
            let s = CStr::from_ptr(ptr).to_str().unwrap();
            assert!(
                s.contains("[mandate]"),
                "test mandate must contain [mandate]"
            );
            a2g_string_free(ptr);
        }
    }
}
