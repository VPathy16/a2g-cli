//! Cockpit domain extension: Communications, Payments, PII (ADR-0018 / SPEC §3.X).
//!
//! ## Namespaces
//!
//! | Namespace | Sub-tools | Classification |
//! |-----------|-----------|---------------|
//! | `comms.call.place`, `comms.sms.send` | — | `CommsSensitiveHitl` — always HITL |
//! | `comms.contacts.read`, `comms.history.read` | — | `CommsReadPiiGated` — requires `pii.grant` |
//! | Unknown `comms.*` | — | `SensitiveHitlUnknown` — fail-closed |
//! | `pay.*` | any | `PayAlwaysHitl` — always HITL |
//! | `pii.profile.export` | — | `Forbidden` — structural hard DENY |
//! | `pii.<ns>.read` | any sub-path ending `.read` | `PiiReadGated` — requires `pii.grant` |
//! | Unknown `pii.*` | — | `SensitiveHitlUnknown` — fail-closed |
//! | Anything else | — | `NonCockpit` — handled by existing pipeline |
//!
//! ## Protocol-freeze compliance
//!
//! This module adds no new fields to `MandateTbs`.  PII access is signalled by
//! the presence of the sentinel capability string `"pii.grant"` in the mandate's
//! `tools` list — an existing field (index 9) that carries capability tokens.
//!
//! ## no_std compatibility
//!
//! `classify_cockpit_tool()` is a pure function with no heap allocation.
//! `Deny` reasons are `&'static str`.  Fully compatible with the no_std scaffold.

/// Capability domain for cockpit (non-vehicle) tools.
///
/// Returned by [`classify_cockpit_tool`].  The enforcement engine branches on this
/// to apply the cockpit-specific rules from ADR-0018.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CockpitDomain {
    /// `comms.call.place`, `comms.sms.send` — communication actions that require
    /// human-in-the-loop approval unconditionally (regardless of `escalate_tools`).
    CommsSensitiveHitl,

    /// `comms.contacts.read`, `comms.history.read` — reads PII from comms subsystem.
    /// Requires the `"pii.grant"` capability sentinel; DENY without it.
    CommsReadPiiGated,

    /// `pay.*` — all payment-namespace tools require HITL unconditionally.
    PayAlwaysHitl,

    /// `pii.<ns>.read` (any sub-namespace `.read` suffix) — reads personal data.
    /// Requires the `"pii.grant"` capability sentinel; DENY without it.
    PiiReadGated,

    /// `pii.profile.export` — structural hard DENY.  No mandate permission,
    /// escalation grant, or vehicle state can override this.  Checked before
    /// any mandate evaluation, identically to the vehicle Forbidden pre-check.
    Forbidden,

    /// Unknown `comms.*`, `pay.*`, or `pii.*` sub-operation — fail-closed
    /// forward-compat: treated as Sensitive requiring HITL.
    SensitiveHitlUnknown,

    /// Not a cockpit-domain tool; handled by the existing enforcement pipeline.
    NonCockpit,
}

impl CockpitDomain {
    /// `true` when the domain requires always-HITL, regardless of `escalate_tools`.
    pub fn always_hitl(self) -> bool {
        matches!(
            self,
            CockpitDomain::CommsSensitiveHitl
                | CockpitDomain::PayAlwaysHitl
                | CockpitDomain::SensitiveHitlUnknown
        )
    }

    /// `true` when the domain requires the `"pii.grant"` capability sentinel.
    pub fn requires_pii_grant(self) -> bool {
        matches!(
            self,
            CockpitDomain::PiiReadGated | CockpitDomain::CommsReadPiiGated
        )
    }
}

/// Classify a tool name into its cockpit capability domain.
///
/// Accepts `comms.*`, `pay.*`, and `pii.*` tool names.  All other names return
/// `CockpitDomain::NonCockpit`.
///
/// Classification is purely prefix-based with no I/O and no heap allocation.
/// Unknown sub-operations within a known namespace resolve to `SensitiveHitlUnknown`
/// rather than `NonCockpit` — this is the fail-closed forward-compat rule.
pub fn classify_cockpit_tool(tool: &str) -> CockpitDomain {
    if tool.starts_with("comms.") {
        return classify_comms(tool);
    }
    if tool.starts_with("pay.") {
        // All pay.* tools require HITL — no exceptions.
        return CockpitDomain::PayAlwaysHitl;
    }
    if tool.starts_with("pii.") {
        return classify_pii(tool);
    }
    CockpitDomain::NonCockpit
}

fn classify_comms(tool: &str) -> CockpitDomain {
    match tool {
        "comms.call.place" | "comms.sms.send" => CockpitDomain::CommsSensitiveHitl,
        "comms.contacts.read" | "comms.history.read" => CockpitDomain::CommsReadPiiGated,
        _ => CockpitDomain::SensitiveHitlUnknown,
    }
}

fn classify_pii(tool: &str) -> CockpitDomain {
    // Structural Forbidden — export creates a persistent artefact outside the vehicle.
    if tool == "pii.profile.export" {
        return CockpitDomain::Forbidden;
    }
    // Any pii sub-path ending in ".read" is PII-gated.
    if tool.ends_with(".read") {
        return CockpitDomain::PiiReadGated;
    }
    // Unknown pii.* operations — fail-closed.
    CockpitDomain::SensitiveHitlUnknown
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_comms_call_place_is_hitl() {
        assert_eq!(
            classify_cockpit_tool("comms.call.place"),
            CockpitDomain::CommsSensitiveHitl
        );
    }

    #[test]
    fn test_comms_sms_send_is_hitl() {
        assert_eq!(
            classify_cockpit_tool("comms.sms.send"),
            CockpitDomain::CommsSensitiveHitl
        );
    }

    #[test]
    fn test_comms_contacts_read_is_pii_gated() {
        assert_eq!(
            classify_cockpit_tool("comms.contacts.read"),
            CockpitDomain::CommsReadPiiGated
        );
    }

    #[test]
    fn test_comms_history_read_is_pii_gated() {
        assert_eq!(
            classify_cockpit_tool("comms.history.read"),
            CockpitDomain::CommsReadPiiGated
        );
    }

    #[test]
    fn test_comms_unknown_subop_is_sensitive_hitl() {
        assert_eq!(
            classify_cockpit_tool("comms.voicemail.delete"),
            CockpitDomain::SensitiveHitlUnknown
        );
        assert_eq!(
            classify_cockpit_tool("comms.future.unknown"),
            CockpitDomain::SensitiveHitlUnknown
        );
    }

    #[test]
    fn test_pay_all_variants_are_always_hitl() {
        for tool in &[
            "pay.toll.charge",
            "pay.parking.start",
            "pay.subscription.manage",
            "pay.anything.new",
        ] {
            assert_eq!(
                classify_cockpit_tool(tool),
                CockpitDomain::PayAlwaysHitl,
                "tool {tool} must be PayAlwaysHitl"
            );
        }
    }

    #[test]
    fn test_pii_profile_export_is_forbidden() {
        assert_eq!(
            classify_cockpit_tool("pii.profile.export"),
            CockpitDomain::Forbidden
        );
    }

    #[test]
    fn test_pii_read_variants_are_pii_gated() {
        for tool in &[
            "pii.contacts.read",
            "pii.location.read",
            "pii.profile.read",
            "pii.health.read",
        ] {
            assert_eq!(
                classify_cockpit_tool(tool),
                CockpitDomain::PiiReadGated,
                "tool {tool} must be PiiReadGated"
            );
        }
    }

    #[test]
    fn test_pii_unknown_subop_is_sensitive_hitl() {
        assert_eq!(
            classify_cockpit_tool("pii.profile.import"),
            CockpitDomain::SensitiveHitlUnknown
        );
        assert_eq!(
            classify_cockpit_tool("pii.future.unknown"),
            CockpitDomain::SensitiveHitlUnknown
        );
    }

    #[test]
    fn test_non_cockpit_tools_pass_through() {
        for tool in &[
            "vehicle.climate.set_temperature",
            "read_file",
            "DOOR_LOCK",
            "comms",       // no dot suffix
            "pay",         // no dot suffix
            "pii",         // no dot suffix
            "payment.foo", // wrong prefix
        ] {
            assert_eq!(
                classify_cockpit_tool(tool),
                CockpitDomain::NonCockpit,
                "tool {tool} must be NonCockpit"
            );
        }
    }

    #[test]
    fn test_always_hitl_predicate() {
        assert!(CockpitDomain::CommsSensitiveHitl.always_hitl());
        assert!(CockpitDomain::PayAlwaysHitl.always_hitl());
        assert!(CockpitDomain::SensitiveHitlUnknown.always_hitl());
        assert!(!CockpitDomain::PiiReadGated.always_hitl());
        assert!(!CockpitDomain::CommsReadPiiGated.always_hitl());
        assert!(!CockpitDomain::Forbidden.always_hitl());
        assert!(!CockpitDomain::NonCockpit.always_hitl());
    }

    #[test]
    fn test_requires_pii_grant_predicate() {
        assert!(CockpitDomain::PiiReadGated.requires_pii_grant());
        assert!(CockpitDomain::CommsReadPiiGated.requires_pii_grant());
        assert!(!CockpitDomain::CommsSensitiveHitl.requires_pii_grant());
        assert!(!CockpitDomain::PayAlwaysHitl.requires_pii_grant());
        assert!(!CockpitDomain::Forbidden.requires_pii_grant());
        assert!(!CockpitDomain::SensitiveHitlUnknown.requires_pii_grant());
        assert!(!CockpitDomain::NonCockpit.requires_pii_grant());
    }
}
