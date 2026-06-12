//! Independent forbidden-domain check (ADR-0010 §Independent Forbidden Re-Check).
//!
//! The gateway maintains its own copy of the forbidden-domain rule, implemented
//! by re-using `a2g_core::vehicle::classify_vehicle_tool` and
//! `a2g_core::cockpit::classify_cockpit_tool`. This is intentional:
//! the same logic runs independently, in the trusted domain, without trusting the
//! rich domain's verdict. Even a validly-signed ALLOW receipt for a forbidden
//! capability is refused at the gateway.
//!
//! This provides defense in depth against:
//! - A bug in a2g-core that mis-evaluates a forbidden tool.
//! - A compromised rich domain that constructs a plausible-looking ALLOW.
//! - A mandate-configuration error that accidentally lists a forbidden tool.
//!
//! ## Cockpit domain extensions (ADR-0018)
//!
//! `is_cockpit_forbidden()` re-checks `pii.profile.export` independently.
//! `requires_hitl_binding()` enforces that always-HITL cockpit tools (`pay.*`,
//! `comms.call.place`, `comms.sms.send`, unknown cockpit sub-operations) can only
//! produce an ALLOW receipt via Phase 2 (binding_id non-empty).  An ALLOW receipt
//! for these tools with an empty binding_id indicates a compromised rich domain.

use a2g_core::cockpit::{classify_cockpit_tool, CockpitDomain};
use a2g_core::vehicle::{classify_vehicle_tool, VehicleDomain};

/// Returns `true` when the tool is in the Vehicle Forbidden domain.
///
/// Called **before** signature verification — a forbidden tool is refused without
/// inspecting the rest of the receipt at all. This is the first gate in the
/// gateway verification sequence (ADR-0010 §Gateway verification steps).
pub fn is_forbidden(tool: &str) -> bool {
    classify_vehicle_tool(tool) == VehicleDomain::Forbidden
}

/// Reason string emitted when a vehicle-forbidden tool is refused.
pub fn refuse_reason(tool: &str) -> String {
    format!(
        "gateway_forbidden_domain: '{}' is in the safety-critical domain \
         and is unconditionally refused regardless of receipt validity",
        tool
    )
}

/// Returns `true` when the tool is in the Cockpit Forbidden domain (ADR-0018).
///
/// Currently only `pii.profile.export`.  Checked immediately after the vehicle
/// forbidden re-check, before signature verification.
pub fn is_cockpit_forbidden(tool: &str) -> bool {
    classify_cockpit_tool(tool) == CockpitDomain::Forbidden
}

/// Reason string emitted when a cockpit-forbidden tool is refused.
pub fn cockpit_forbidden_reason(tool: &str) -> String {
    format!(
        "gateway_cockpit_forbidden: '{}' is structurally forbidden (ADR-0018) \
         and is unconditionally refused regardless of receipt validity",
        tool
    )
}

/// Returns `true` when the tool requires a Phase 2 HITL binding on every ALLOW.
///
/// `pay.*`, `comms.call.place`, `comms.sms.send`, and unknown cockpit namespaces
/// can only produce an ALLOW verdict via Phase 2 (after human approval).  An ALLOW
/// receipt for these tools with an empty `binding_id` indicates the rich domain
/// was bypassed or compromised.
pub fn requires_hitl_binding(tool: &str) -> bool {
    classify_cockpit_tool(tool).always_hitl()
}
