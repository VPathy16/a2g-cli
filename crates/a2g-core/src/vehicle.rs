//! Vehicle capability taxonomy for in-cabin automotive agents.
//!
//! ## Domains
//!
//! | Domain | Prefix | Default | State-gated |
//! |--------|--------|---------|-------------|
//! | Comfort | `vehicle.climate.*`, `vehicle.seat.*`, `vehicle.lighting.*`, `vehicle.media.*` | ALLOW | No |
//! | Convenience | `vehicle.navigation.*`, `vehicle.phone.*` | ALLOW | Light only |
//! | Sensitive | `vehicle.door.*`, `vehicle.window.*`, `vehicle.trunk.*`, `vehicle.lock.*` | ESCALATE | Yes (park+stopped) |
//! | Forbidden | `vehicle.powertrain.*`, `vehicle.chassis.*`, `vehicle.adas.*`, `vehicle.drive.*`, `vehicle.steering.*`, `vehicle.braking.*`, `vehicle.throttle.*` | hard DENY | N/A — denied before gating |
//!
//! ## no_std compatibility
//!
//! `classify_vehicle_tool()` and `evaluate_vehicle_state()` are pure functions with
//! no heap allocation on the `Allow` path. `StateVerdict::Deny` carries a `&'static str`
//! reason to avoid heap. `extract_vehicle_state()` uses `serde_json` (already a blocker).

use serde::{Deserialize, Serialize};

/// The four capability domains for `vehicle.*` tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VehicleDomain {
    /// climate, seat, ambient lighting, media → always ALLOW regardless of speed or actor.
    Comfort,
    /// navigation, phone, media playback → ALLOW; light gating only.
    Convenience,
    /// door, window, trunk, lock → ESCALATE by default; additionally state-gated
    /// (park + stopped required). State denial emits DENY before escalation runs.
    Sensitive,
    /// powertrain, chassis, adas, drive, steering, braking, throttle →
    /// **unconditional hard DENY**. No mandate permission, escalation, or vehicle
    /// state can override this. Checked before any mandate evaluation.
    Forbidden,
    /// Not a `vehicle.*` tool — passes through to the generic enforcement pipeline.
    NonVehicle,
}

/// Vehicle gear selector position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gear {
    Park,
    Reverse,
    Neutral,
    Drive,
}

/// Who is making the request in the vehicle cabin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    Driver,
    Passenger,
}

/// Current vehicle physical state, supplied as context at decision time.
///
/// Passed in the `vehicle_state` key of the params JSON:
/// ```json
/// {"speed_kph": 0.0, "gear": "Park", "actor": "Driver"}
/// ```
///
/// If absent for a `Sensitive` capability, `VehicleState::fail_safe()` is used —
/// assumes highway speed in Drive, so sensitive actions are **DENIED by omission**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleState {
    /// Speed in km/h. Values < 0 are clamped to 0.
    pub speed_kph: f64,
    /// Current gear selector position.
    pub gear: Gear,
    /// Who is making the request.
    pub actor: Actor,
}

impl VehicleState {
    /// Fail-safe worst-case default: 999 km/h in Drive.
    ///
    /// Used when no `vehicle_state` is provided. Ensures sensitive capabilities
    /// are denied by omission rather than accidentally allowed.
    pub fn fail_safe() -> Self {
        VehicleState {
            speed_kph: 999.0,
            gear: Gear::Drive,
            actor: Actor::Driver,
        }
    }

    /// `true` when the vehicle is safely stationary in Park.
    /// Required for all Sensitive capabilities (window, door, trunk, lock).
    pub fn is_parked_and_stopped(&self) -> bool {
        let speed = if self.speed_kph < 0.0 {
            0.0
        } else {
            self.speed_kph
        };
        speed < 5.0 && self.gear == Gear::Park
    }
}

/// Result of the vehicle-state evaluation step.
///
/// `&'static str` reason avoids heap allocation and keeps this type `no_std`-compatible.
#[derive(Debug, Clone, PartialEq)]
pub enum StateVerdict {
    /// State constraints satisfied; proceed with the capability.
    Allow,
    /// State constraint violated; the reason is the policy rule string.
    Deny(&'static str),
}

/// Classify a tool name into its vehicle capability domain.
///
/// Matching is prefix-based on the `vehicle.<domain>` segment.
/// Unknown `vehicle.*` sub-domains are treated as `Sensitive` (fail-safe).
pub fn classify_vehicle_tool(tool: &str) -> VehicleDomain {
    if !tool.starts_with("vehicle.") {
        return VehicleDomain::NonVehicle;
    }

    // Forbidden — safety wall, checked first.
    if tool.starts_with("vehicle.powertrain.")
        || tool.starts_with("vehicle.chassis.")
        || tool.starts_with("vehicle.adas.")
        || tool.starts_with("vehicle.drive.")
        || tool.starts_with("vehicle.steering.")
        || tool.starts_with("vehicle.braking.")
        || tool.starts_with("vehicle.throttle.")
    {
        return VehicleDomain::Forbidden;
    }

    // Sensitive — escalate by default, park+stopped required.
    if tool.starts_with("vehicle.door.")
        || tool.starts_with("vehicle.window.")
        || tool.starts_with("vehicle.trunk.")
        || tool.starts_with("vehicle.lock.")
    {
        return VehicleDomain::Sensitive;
    }

    // Convenience — allow with light gating.
    if tool.starts_with("vehicle.navigation.") || tool.starts_with("vehicle.phone.") {
        return VehicleDomain::Convenience;
    }

    // Comfort — always allow.
    if tool.starts_with("vehicle.climate.")
        || tool.starts_with("vehicle.seat.")
        || tool.starts_with("vehicle.lighting.")
        || tool.starts_with("vehicle.media.")
    {
        return VehicleDomain::Comfort;
    }

    // Unknown vehicle.* sub-domain → Sensitive (fail-safe).
    VehicleDomain::Sensitive
}

/// Pure vehicle-state evaluation for Sensitive capabilities.
///
/// Called by `decide()` after the forbidden-domain pre-check and after boundary
/// checks (step 4), only for `VehicleDomain::Sensitive` tools. Returns `Allow`
/// when state constraints are satisfied, or `Deny(&'static str)` otherwise.
///
/// ## Rules
///
/// - `vehicle.window.*`, `vehicle.door.*`, `vehicle.trunk.*`, `vehicle.lock.*`:
///   ALLOW only when `speed_kph < 5.0 AND gear == Park`.
/// - Unknown Sensitive sub-domains: same park+stopped rule (fail-safe).
/// - Comfort capabilities are **never** evaluated here (wrong domain; callers
///   must only invoke this for `Sensitive` tools).
///
/// ## no_std
///
/// No I/O, no wall-clock, no heap on the `Allow` path. `Deny` carries a
/// `&'static str` reason. Fully compatible with the no_std scaffold.
pub fn evaluate_vehicle_state(_tool: &str, state: &VehicleState) -> StateVerdict {
    // All Sensitive sub-domains require parked and stopped.
    if !state.is_parked_and_stopped() {
        return StateVerdict::Deny(
            "vehicle_state_violation: sensitive capabilities (window/door/trunk/lock) \
             require speed_kph < 5.0 and gear == Park",
        );
    }
    StateVerdict::Allow
}

/// Extract a `VehicleState` from the `vehicle_state` key in params JSON.
///
/// Falls back to `VehicleState::fail_safe()` if the key is absent or cannot
/// be deserialized, so omitting state for a Sensitive capability is safe by default.
pub fn extract_vehicle_state(params: &serde_json::Value) -> VehicleState {
    params
        .get("vehicle_state")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(VehicleState::fail_safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classification ───────────────────────────────────────────────────────

    #[test]
    fn test_classify_comfort() {
        assert_eq!(
            classify_vehicle_tool("vehicle.climate.set_temperature"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.seat.adjust_lumbar"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.lighting.set_ambient"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.media.set_volume"),
            VehicleDomain::Comfort
        );
    }

    #[test]
    fn test_classify_convenience() {
        assert_eq!(
            classify_vehicle_tool("vehicle.navigation.set_destination"),
            VehicleDomain::Convenience
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.phone.call"),
            VehicleDomain::Convenience
        );
    }

    #[test]
    fn test_classify_sensitive() {
        assert_eq!(
            classify_vehicle_tool("vehicle.window.set_position"),
            VehicleDomain::Sensitive
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.door.unlock"),
            VehicleDomain::Sensitive
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.trunk.open"),
            VehicleDomain::Sensitive
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.lock.lock_all"),
            VehicleDomain::Sensitive
        );
    }

    #[test]
    fn test_classify_forbidden() {
        assert_eq!(
            classify_vehicle_tool("vehicle.powertrain.start_engine"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.chassis.adjust_suspension"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.adas.override_cruise"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.drive.set_mode"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.steering.set_angle"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.braking.apply_emergency"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("vehicle.throttle.set_position"),
            VehicleDomain::Forbidden
        );
    }

    #[test]
    fn test_classify_non_vehicle() {
        assert_eq!(
            classify_vehicle_tool("read_file"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(classify_vehicle_tool("vehicle"), VehicleDomain::NonVehicle); // no dot
        assert_eq!(
            classify_vehicle_tool("vehicle_sensor"),
            VehicleDomain::NonVehicle
        );
    }

    // ── State evaluation ─────────────────────────────────────────────────────

    #[test]
    fn test_parked_stopped_allows_sensitive() {
        let state = VehicleState {
            speed_kph: 0.0,
            gear: Gear::Park,
            actor: Actor::Driver,
        };
        assert!(state.is_parked_and_stopped());
        assert_eq!(
            evaluate_vehicle_state("vehicle.window.open", &state),
            StateVerdict::Allow
        );
        assert_eq!(
            evaluate_vehicle_state("vehicle.door.unlock", &state),
            StateVerdict::Allow
        );
    }

    #[test]
    fn test_moving_denies_sensitive() {
        let state = VehicleState {
            speed_kph: 30.0,
            gear: Gear::Drive,
            actor: Actor::Driver,
        };
        let v = evaluate_vehicle_state("vehicle.window.set_position", &state);
        match v {
            StateVerdict::Deny(r) => assert!(r.contains("vehicle_state_violation")),
            StateVerdict::Allow => panic!("expected Deny for moving vehicle"),
        }
    }

    #[test]
    fn test_speed_below_threshold_but_not_park_denies() {
        let state = VehicleState {
            speed_kph: 3.0,
            gear: Gear::Drive, // still in Drive
            actor: Actor::Passenger,
        };
        assert_eq!(
            evaluate_vehicle_state("vehicle.door.unlock", &state),
            StateVerdict::Deny(
                "vehicle_state_violation: sensitive capabilities (window/door/trunk/lock) \
                 require speed_kph < 5.0 and gear == Park"
            )
        );
    }

    #[test]
    fn test_park_gear_high_speed_denies() {
        // Physically impossible, but the engine must be fail-safe.
        let state = VehicleState {
            speed_kph: 60.0,
            gear: Gear::Park,
            actor: Actor::Driver,
        };
        assert!(!state.is_parked_and_stopped());
        assert!(matches!(
            evaluate_vehicle_state("vehicle.window.open", &state),
            StateVerdict::Deny(_)
        ));
    }

    #[test]
    fn test_fail_safe_default_denies_sensitive() {
        let params = serde_json::json!({}); // no vehicle_state
        let state = extract_vehicle_state(&params);
        assert!(state.speed_kph > 5.0);
        assert_eq!(state.gear, Gear::Drive);
        assert!(matches!(
            evaluate_vehicle_state("vehicle.window.open", &state),
            StateVerdict::Deny(_)
        ));
    }

    #[test]
    fn test_extract_valid_state() {
        let params = serde_json::json!({
            "vehicle_state": {"speed_kph": 0.0, "gear": "Park", "actor": "Passenger"}
        });
        let state = extract_vehicle_state(&params);
        assert_eq!(state.gear, Gear::Park);
        assert_eq!(state.actor, Actor::Passenger);
        assert!(state.is_parked_and_stopped());
    }
}
