//! Independent forbidden-domain check (ADR-0010 §Independent Forbidden Re-Check).
//!
//! The gateway maintains its own copy of the forbidden-domain rule, implemented
//! by re-using `a2g_core::vehicle::classify_vehicle_tool`. This is intentional:
//! the same logic runs independently, in the trusted domain, without trusting the
//! rich domain's verdict. Even a validly-signed ALLOW receipt for a forbidden
//! capability is refused at the gateway.
//!
//! This provides defense in depth against:
//! - A bug in a2g-core that mis-evaluates a forbidden tool.
//! - A compromised rich domain that constructs a plausible-looking ALLOW.
//! - A mandate-configuration error that accidentally lists a forbidden tool.

use a2g_core::vehicle::{classify_vehicle_tool, VehicleDomain};

/// Returns `true` when the tool is in the Forbidden domain.
///
/// Called **before** signature verification — a forbidden tool is refused without
/// inspecting the rest of the receipt at all. This is the first gate in the
/// gateway verification sequence (ADR-0010 §Gateway verification steps).
pub fn is_forbidden(tool: &str) -> bool {
    classify_vehicle_tool(tool) == VehicleDomain::Forbidden
}

/// Reason string emitted when a forbidden tool is refused.
pub fn refuse_reason(tool: &str) -> String {
    format!(
        "gateway_forbidden_domain: '{}' is in the safety-critical domain \
         and is unconditionally refused regardless of receipt validity",
        tool
    )
}
