//! Vehicle capability taxonomy for in-cabin automotive agents.
//!
//! ## Domains
//!
//! | Domain | Prefix | VHAL examples | Default | State-gated |
//! |--------|--------|---------------|---------|-------------|
//! | Comfort | `vehicle.climate.*`, `vehicle.seat.*`, `vehicle.lighting.*`, `vehicle.media.*` | `HVAC_TEMPERATURE_SET`, `HVAC_SEAT_TEMPERATURE`, `CABIN_LIGHTS_SWITCH` | ALLOW | No |
//! | Convenience | `vehicle.navigation.*`, `vehicle.phone.*` | (no standard VHAL names; use `vehicle.navigation.*` / `vehicle.phone.*` prefix form) | ALLOW | Light only |
//! | Sensitive | `vehicle.door.*`, `vehicle.window.*`, `vehicle.trunk.*`, `vehicle.lock.*` | `DOOR_LOCK`, `WINDOW_POS`, `WINDOW_MOVE`, `EV_CHARGE_PORT_OPEN` | ESCALATE | Yes (park+stopped) |
//! | Forbidden | `vehicle.powertrain.*`, `vehicle.chassis.*`, `vehicle.adas.*`, `vehicle.drive.*`, `vehicle.steering.*`, `vehicle.braking.*`, `vehicle.throttle.*` | `CRUISE_CONTROL_COMMAND`, `LANE_CENTERING_ASSIST_COMMAND`, `EV_STOPPING_MODE` | hard DENY | N/A — denied before gating |
//!
//! ## VHAL property name support
//!
//! `classify_vehicle_tool()` accepts both our `vehicle.<domain>.<action>` strings
//! **and** AAOS `VehicleProperty` symbolic names directly
//! (e.g. `"HVAC_TEMPERATURE_SET"`, `"DOOR_LOCK"`, `"CRUISE_CONTROL_COMMAND"`).
//! Both forms resolve to the same domain.
//!
//! Read-only telemetry properties (`PERF_VEHICLE_SPEED`, `ENGINE_RPM`, `GEAR_SELECTION`
//! in their read role) resolve to `NonVehicle` — they are state sources used for
//! gating, not agent-initiated actions that require governance.
//!
//! The forbidden rule is specifically about **write access** to propulsion, ADAS,
//! and chassis-safety properties. A2G mediates between the agent and VHAL; the agent
//! never calls VHAL directly and never bypasses A2G enforcement.
//!
//! ## AAOS VHAL state fields
//!
//! Vehicle-state gating reads from two AAOS properties:
//! - `PERF_VEHICLE_SPEED` (VehicleProperty 0x11600207, m/s) → converted and stored as `speed_mmps`
//! - `GEAR_SELECTION` (VehicleProperty 0x11400400) → stored as `gear`
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
    ///
    /// In VHAL terms: write access to propulsion, ADAS, and chassis-safety properties
    /// (e.g. `CRUISE_CONTROL_COMMAND`, `LANE_CENTERING_ASSIST_COMMAND`, `EV_STOPPING_MODE`).
    Forbidden,
    /// Not a `vehicle.*` tool and not a known VHAL write-capability —
    /// passes through to the generic enforcement pipeline.
    ///
    /// Read-only VHAL telemetry properties (`PERF_VEHICLE_SPEED`, `ENGINE_RPM`,
    /// `GEAR_SELECTION`) resolve here — the agent may observe vehicle state, but
    /// that observation is not itself a governed capability.
    NonVehicle,
}

/// Vehicle gear selector position.
///
/// Maps to AAOS `VehicleGear` / `GEAR_SELECTION` (VehicleProperty 0x11400400):
/// - `Park`    ≙ `GEAR_PARK`    (0x04)
/// - `Reverse` ≙ `GEAR_REVERSE` (0x08)
/// - `Neutral` ≙ `GEAR_NEUTRAL` (0x10)
/// - `Drive`   ≙ `GEAR_DRIVE`   (0x20)
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

/// Speed threshold for the "parked and stopped" gate: 5.0 km/h ≈ 1388.9 mm/s, rounded up.
///
/// `speed_mmps < SPEED_GATE_MMPS` is the fixed-point equivalent of `speed_kph < 5.0`.
/// Gate condition: **strictly less than** this value.
pub const SPEED_GATE_MMPS: u32 = 1_389;

/// Fail-safe speed for the worst-case default state (999 km/h expressed in mm/s).
///
/// 999 km/h × (1 000 000 mm/km) ÷ (3 600 s/h) = 277 500 mm/s exactly.
pub const FAIL_SAFE_SPEED_MMPS: u32 = 277_500;

/// Maximum speed accepted at the ingress boundary (km/h).
///
/// Speeds above this value are rejected by [`speed_kph_to_mmps`] with an error.
pub const SPEED_MAX_KPH: f64 = 1_000.0;

/// Convert a floating-point speed in km/h to the canonical fixed-point representation.
///
/// This is the **sole** float-to-integer conversion on the vehicle-state path.
/// All validation happens here; `VehicleState.speed_mmps` is always a valid integer.
///
/// ## Rejection rule
///
/// The following inputs are rejected (return `Err`), mapping to fail-safe DENY at
/// the call site:
///
/// | Input condition         | Reason                        |
/// |-------------------------|-------------------------------|
/// | NaN                     | not a number                  |
/// | ±Infinity               | infinite speed                |
/// | Negative (`< 0.0`)      | physically impossible         |
/// | Subnormal               | out-of-range near zero        |
/// | `> SPEED_MAX_KPH`       | exceeds maximum accepted speed |
///
/// ## Encoding
///
/// Valid inputs are converted by: `round(speed_kph × 1 000 000 ÷ 3 600)`.
/// The result fits in `u32` for all inputs ≤ `SPEED_MAX_KPH` (max ≈ 277 778 mm/s).
///
/// The 5.0 km/h gate threshold (1388.888… mm/s) rounds to [`SPEED_GATE_MMPS`] = 1 389.
/// Effective threshold precision: ± 1 mm/s (≈ 0.0036 km/h).
pub fn speed_kph_to_mmps(speed_kph: f64) -> Result<u32, &'static str> {
    if speed_kph.is_nan() {
        return Err("speed_kph_to_mmps: speed is NaN");
    }
    if speed_kph.is_infinite() {
        return Err("speed_kph_to_mmps: speed is infinite");
    }
    if speed_kph < 0.0 {
        return Err("speed_kph_to_mmps: speed is negative");
    }
    if speed_kph.is_subnormal() {
        return Err("speed_kph_to_mmps: speed is subnormal");
    }
    if speed_kph > SPEED_MAX_KPH {
        return Err("speed_kph_to_mmps: speed exceeds SPEED_MAX_KPH");
    }
    // Validated range: [0.0, 1000.0] → [0, 277_778] mm/s — well within u32::MAX.
    let mmps_f = speed_kph * (1_000_000.0_f64 / 3_600.0_f64);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(mmps_f.round() as u32)
}

/// Current vehicle physical state, supplied as context at decision time.
///
/// Field names and semantics map to AAOS VHAL properties:
/// - `speed_mmps` — fixed-point speed in mm/s. Sourced from `PERF_VEHICLE_SPEED`
///   (m/s in AAOS); the caller validates and converts via [`speed_kph_to_mmps`]
///   before constructing this struct. No `f64` reaches the decision path.
/// - `gear` — sourced from `GEAR_SELECTION` (VehicleProperty 0x11400400) or
///   `CURRENT_GEAR` (VehicleProperty 0x11400401).
/// - `actor` — derived from the active UX session (driver vs. passenger zone).
///
/// Passed in the `vehicle_state` key of the params JSON:
/// ```json
/// {"speed_mmps": 0, "gear": "Park", "actor": "Driver"}
/// ```
///
/// If absent for a `Sensitive` capability, `VehicleState::fail_safe()` is used —
/// assumes highway speed in Drive, so sensitive actions are **DENIED by omission**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleState {
    /// Speed in mm/s (fixed-point). Converted from `PERF_VEHICLE_SPEED` (m/s in AAOS)
    /// at the ingress boundary via [`speed_kph_to_mmps`]. No float on the decision path.
    pub speed_mmps: u32,
    /// Current gear selector position. Corresponds to `GEAR_SELECTION` / `CURRENT_GEAR`.
    pub gear: Gear,
    /// Who is making the request.
    pub actor: Actor,
}

impl VehicleState {
    /// Fail-safe worst-case default: `FAIL_SAFE_SPEED_MMPS` (999 km/h) in Drive.
    ///
    /// Used when no `vehicle_state` is provided. Ensures sensitive capabilities
    /// are denied by omission rather than accidentally allowed.
    pub fn fail_safe() -> Self {
        VehicleState {
            speed_mmps: FAIL_SAFE_SPEED_MMPS,
            gear: Gear::Drive,
            actor: Actor::Driver,
        }
    }

    /// `true` when the vehicle is safely stationary in Park.
    ///
    /// Evaluates: `speed_mmps < SPEED_GATE_MMPS AND GEAR_SELECTION == GEAR_PARK`.
    /// Equivalent to the float condition `speed_kph < 5.0 AND gear == Park`,
    /// but computed entirely in integer arithmetic — no float on the decision path.
    /// Required for all Sensitive capabilities (window, door, trunk, lock).
    pub fn is_parked_and_stopped(&self) -> bool {
        self.speed_mmps < SPEED_GATE_MMPS && self.gear == Gear::Park
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

// ── VHAL Property Mapping ────────────────────────────────────────────────────

/// AAOS VehicleProperty access mode.
///
/// Reflects whether the property is read-only (telemetry), write-only (command),
/// or bidirectional. Used to determine domain classification:
/// `Read`-only properties are state sources (telemetry), not agent capabilities,
/// so they resolve to `NonVehicle` regardless of their conceptual domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhalAccessMode {
    /// Property is read-only (telemetry/status). Resolves to `NonVehicle`.
    Read,
    /// Property is write-only (command). Resolves to the mapped domain.
    Write,
    /// Property supports both read and write. Resolves to the mapped domain.
    ReadWrite,
}

/// Mapping from an AAOS `VehicleProperty` symbolic name to A2G's capability domain.
///
/// The `domain` field records the conceptual domain even for `Read`-only entries
/// (for documentation purposes). The effective classification of `Read`-only entries
/// is always `NonVehicle` — the agent observes state but does not command anything.
pub struct VhalPropertyMapping {
    /// AAOS `VehicleProperty` symbolic name (e.g. `"HVAC_TEMPERATURE_SET"`).
    pub name: &'static str,
    /// Access mode of this property in AAOS.
    pub access: VhalAccessMode,
    /// A2G capability domain for write/readwrite operations.
    pub domain: VehicleDomain,
    /// One-line description for documentation.
    pub description: &'static str,
}

/// AAOS VehicleProperty → A2G domain mapping table.
///
/// Property names match the symbolic constants in
/// `android.hardware.automotive.vehicle.VehicleProperty` (AAOS VHAL HAL definition).
/// Integer IDs are noted in comments for cross-reference; A2G uses only symbolic names.
/// All IDs verified against AOSP VehiclePropertyIds.java (master) and
/// hardware/interfaces/automotive/vehicle/2.0/types.hal; see docs/aaos-vhal-verification.md.
///
/// Read-only entries (telemetry) resolve to `NonVehicle` in `classify_vhal_property()`.
/// The `domain` field on those rows is the conceptual tier for documentation only.
pub static VHAL_PROPERTIES: &[VhalPropertyMapping] = &[
    // ── Comfort: HVAC ────────────────────────────────────────────────────────
    VhalPropertyMapping {
        name: "HVAC_TEMPERATURE_SET", // 0x15600503
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Set per-zone cabin target temperature",
    },
    VhalPropertyMapping {
        name: "HVAC_FAN_SPEED", // 0x15400500
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Set HVAC fan speed level",
    },
    VhalPropertyMapping {
        name: "HVAC_FAN_DIRECTION", // 0x15400501
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Set HVAC airflow direction",
    },
    VhalPropertyMapping {
        name: "HVAC_POWER_ON", // 0x15200510
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Toggle HVAC system power",
    },
    VhalPropertyMapping {
        name: "HVAC_DEFROSTER", // 0x13200504 — WINDOW area, BOOLEAN
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Toggle front/rear defroster",
    },
    VhalPropertyMapping {
        name: "HVAC_AUTO_ON", // 0x1520050A
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Toggle HVAC automatic mode",
    },
    VhalPropertyMapping {
        name: "HVAC_TEMPERATURE_CURRENT", // 0x15600502 — READ
        access: VhalAccessMode::Read,
        domain: VehicleDomain::Comfort,
        description: "Read current cabin temperature (telemetry; read-only)",
    },
    VhalPropertyMapping {
        name: "HVAC_SEAT_TEMPERATURE", // 0x1540050B
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Set seat heating or cooling level",
    },
    // ── Comfort: Seat adjustment ─────────────────────────────────────────────
    VhalPropertyMapping {
        name: "SEAT_MEMORY_SELECT", // 0x15400B80
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Comfort,
        description: "Recall a stored seat memory preset",
    },
    VhalPropertyMapping {
        name: "SEAT_FORE_AFT_MOVE", // 0x15400B86
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Comfort,
        description: "Move seat forward or rearward",
    },
    VhalPropertyMapping {
        name: "SEAT_HEIGHT_MOVE", // 0x15400B8C
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Comfort,
        description: "Raise or lower seat height",
    },
    VhalPropertyMapping {
        name: "SEAT_LUMBAR_FORE_AFT_MOVE", // 0x15400B92
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Comfort,
        description: "Adjust lumbar support depth",
    },
    VhalPropertyMapping {
        name: "SEAT_HEADREST_ANGLE_MOVE", // 0x15400B98
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Comfort,
        description: "Adjust headrest angle",
    },
    // ── Comfort: Cabin lighting ──────────────────────────────────────────────
    VhalPropertyMapping {
        name: "CABIN_LIGHTS_SWITCH", // 0x11400F02
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Control cabin interior light switch state",
    },
    VhalPropertyMapping {
        name: "CABIN_LIGHTS_STATE", // 0x11400F01 — READ
        access: VhalAccessMode::Read,
        domain: VehicleDomain::Comfort,
        description: "Read cabin light state (telemetry; read-only)",
    },
    VhalPropertyMapping {
        name: "READING_LIGHTS_SWITCH", // 0x15400F04
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Toggle individual reading lights per zone",
    },
    VhalPropertyMapping {
        name: "DISPLAY_BRIGHTNESS", // 0x11400A03
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Comfort,
        description: "Set infotainment display brightness",
    },
    // ── Sensitive: Windows ───────────────────────────────────────────────────
    VhalPropertyMapping {
        name: "WINDOW_POS", // 0x13400BC0
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Sensitive,
        description: "Set window absolute position (0=closed, 100=fully open)",
    },
    VhalPropertyMapping {
        name: "WINDOW_MOVE", // 0x13400BC1
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Sensitive,
        description: "Command continuous window movement (signed velocity)",
    },
    // ── Sensitive: Doors and charge port ────────────────────────────────────
    VhalPropertyMapping {
        name: "DOOR_LOCK", // 0x16200B02 — DOOR area, BOOLEAN
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Sensitive,
        description: "Lock or unlock a door",
    },
    VhalPropertyMapping {
        name: "DOOR_MOVE", // 0x16400B01
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Sensitive,
        description: "Command powered door open/close movement",
    },
    VhalPropertyMapping {
        name: "EV_CHARGE_PORT_OPEN", // 0x1120030A — GLOBAL, BOOLEAN
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Sensitive,
        description: "Open or close EV charge port door",
    },
    // ── State-source telemetry: read-only → NonVehicle ───────────────────────
    // These are the VHAL properties that feed VehicleState for gating.
    // Reading them is allowed; the agent may not write to them.
    VhalPropertyMapping {
        name: "PERF_VEHICLE_SPEED", // 0x11600207 — READ (m/s)
        access: VhalAccessMode::Read,
        domain: VehicleDomain::NonVehicle,
        description:
            "Current vehicle speed in m/s; converted to mm/s via speed_kph_to_mmps() at ingress",
    },
    VhalPropertyMapping {
        name: "PERF_VEHICLE_SPEED_DISPLAY", // 0x11600208 — READ (m/s, display-filtered)
        access: VhalAccessMode::Read,
        domain: VehicleDomain::NonVehicle,
        description: "Display-filtered vehicle speed (speedometer value)",
    },
    VhalPropertyMapping {
        name: "GEAR_SELECTION",       // 0x11400400 — READ_WRITE
        access: VhalAccessMode::Read, // Agent reads only; writing gear is propulsion-class
        domain: VehicleDomain::NonVehicle,
        description: "Selected gear (Park/Reverse/Neutral/Drive); maps to VehicleState::gear",
    },
    VhalPropertyMapping {
        name: "CURRENT_GEAR", // 0x11400401 — READ
        access: VhalAccessMode::Read,
        domain: VehicleDomain::NonVehicle,
        description: "Currently engaged gear (actual, may differ from selected during shift)",
    },
    VhalPropertyMapping {
        name: "ENGINE_RPM", // 0x11600305 — READ
        access: VhalAccessMode::Read,
        domain: VehicleDomain::NonVehicle,
        description: "Engine RPM (telemetry; read-only)",
    },
    VhalPropertyMapping {
        name: "IGNITION_STATE", // 0x11400409 — READ
        access: VhalAccessMode::Read,
        domain: VehicleDomain::NonVehicle,
        description: "Ignition / engine-running state (telemetry; read-only)",
    },
    // ── Forbidden: write to ADAS / propulsion / chassis-safety ───────────────
    // These properties control safety-critical vehicle systems.
    // WRITE access is unconditionally DENIED; no mandate can override this.
    VhalPropertyMapping {
        name: "CRUISE_CONTROL_COMMAND", // 0x11401012 — GLOBAL, INT32
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Forbidden,
        description: "Write ADAS adaptive cruise-control command (ADAS write — Forbidden)",
    },
    VhalPropertyMapping {
        name: "LANE_CENTERING_ASSIST_COMMAND", // 0x1140100B — GLOBAL, INT32
        access: VhalAccessMode::Write,
        domain: VehicleDomain::Forbidden,
        description: "Write lane-centering assist command (ADAS write — Forbidden)",
    },
    VhalPropertyMapping {
        name: "HANDS_ON_DETECTION_ENABLED", // 0x11201016 — GLOBAL, BOOLEAN
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Forbidden,
        description: "Enable/disable hands-on detection (ADAS safety override — Forbidden)",
    },
    VhalPropertyMapping {
        name: "ELECTRONIC_STABILITY_CONTROL_ENABLED", // 0x1120040E — GLOBAL, BOOLEAN
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Forbidden,
        description: "Enable/disable electronic stability control (chassis safety — Forbidden)",
    },
    VhalPropertyMapping {
        name: "EV_STOPPING_MODE", // 0x1140040D — GLOBAL, INT32
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Forbidden,
        description: "Set one-pedal/creep drive regen mode (propulsion write — Forbidden)",
    },
    VhalPropertyMapping {
        name: "EV_CHARGE_CURRENT_DRAW_LIMIT", // 0x11600F3F — GLOBAL, FLOAT
        access: VhalAccessMode::ReadWrite,
        domain: VehicleDomain::Forbidden,
        description: "Override maximum charge current draw (propulsion write — Forbidden)",
    },
];

/// Classify an AAOS `VehicleProperty` symbolic name into a capability domain.
///
/// `Read`-only entries always resolve to `NonVehicle` regardless of their `domain`
/// field — they are telemetry sources, not agent-initiated commands.
/// Unknown property names resolve to `NonVehicle` (pass through generic pipeline).
fn classify_vhal_property(name: &str) -> VehicleDomain {
    for m in VHAL_PROPERTIES {
        if m.name == name {
            return if m.access == VhalAccessMode::Read {
                VehicleDomain::NonVehicle
            } else {
                m.domain
            };
        }
    }
    VehicleDomain::NonVehicle
}

/// Classify a tool name into its vehicle capability domain.
///
/// Accepts two forms:
/// 1. `vehicle.<domain>.<action>` strings (PR #7 convention) — prefix-based matching.
/// 2. AAOS `VehicleProperty` symbolic names (e.g. `"HVAC_TEMPERATURE_SET"`,
///    `"DOOR_LOCK"`, `"CRUISE_CONTROL_COMMAND"`) — table lookup via [`VHAL_PROPERTIES`].
///
/// Both forms resolve to the same domain. Unknown names that match neither form
/// return `NonVehicle` and pass through the generic enforcement pipeline.
///
/// Unknown `vehicle.*` sub-domains are treated as `Sensitive` (fail-safe).
pub fn classify_vehicle_tool(tool: &str) -> VehicleDomain {
    if tool.starts_with("vehicle.") {
        // ── vehicle.* prefix path (unchanged from PR #7) ────────────────────

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
        return VehicleDomain::Sensitive;
    }

    // ── VHAL property name path ──────────────────────────────────────────────
    classify_vhal_property(tool)
}

/// Pure vehicle-state evaluation for Sensitive capabilities.
///
/// Called by `decide()` after the forbidden-domain pre-check and after boundary
/// checks (step 4), only for `VehicleDomain::Sensitive` tools. Returns `Allow`
/// when state constraints are satisfied, or `Deny(&'static str)` otherwise.
///
/// ## Rules
///
/// - `vehicle.window.*`, `vehicle.door.*`, `vehicle.trunk.*`, `vehicle.lock.*`,
///   `WINDOW_POS`, `WINDOW_MOVE`, `DOOR_LOCK`, `DOOR_MOVE`, `EV_CHARGE_PORT_OPEN`:
///   ALLOW only when `PERF_VEHICLE_SPEED < 5.0 km/h AND GEAR_SELECTION == Park`.
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
             require speed_mmps < 1389 (< 5.0 km/h) and gear == Park",
        );
    }
    StateVerdict::Allow
}

/// Extract a `VehicleState` from the `vehicle_state` key in params JSON.
///
/// Expects `{"speed_mmps": <u32>, "gear": "Park"|"Drive"|"Reverse"|"Neutral",
/// "actor": "Driver"|"Passenger"}`. Falls back to `VehicleState::fail_safe()`
/// if the key is absent or cannot be deserialized, so omitting state for a
/// Sensitive capability is safe by default.
pub fn extract_vehicle_state(params: &serde_json::Value) -> VehicleState {
    params
        .get("vehicle_state")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(VehicleState::fail_safe)
}

// ── Attested Vehicle State (ADR-0007) ────────────────────────────────────────

/// Tracks how vehicle state was attested before reaching `decide()`.
///
/// Recorded in `Verdict.state_trust` so auditors can distinguish decisions
/// made on cryptographically-attested state from those on operator-typed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTrust {
    /// State verified by [`AttestedVehicleState::verify`]: signature + freshness passed.
    Attested,
    /// State entered via [`VerifiedVehicleState::from_operator_trusted`] (ADR-0007 §4).
    /// No cryptographic proof; the operator is accountable for accuracy.
    OperatorTrusted,
    /// No vehicle state was supplied; fail-safe was used (or tool is non-vehicle).
    None,
}

impl StateTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            StateTrust::Attested => "attested",
            StateTrust::OperatorTrusted => "operator_trusted",
            StateTrust::None => "none",
        }
    }
}

/// Error conditions when verifying an [`AttestedVehicleState`].
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationError {
    /// ed25519 signature did not verify against the declared attester public key.
    BadSignature,
    /// Public key bytes are not a valid ed25519 key.
    InvalidPubkey,
    /// Nonce did not match the expected challenge (challenge–response freshness).
    StaleNonce,
    /// Attested timestamp is outside the acceptable freshness window.
    Stale,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::BadSignature => write!(f, "attestation signature did not verify"),
            AttestationError::InvalidPubkey => write!(f, "attester public key is invalid"),
            AttestationError::StaleNonce => write!(f, "nonce mismatch: replay or stale state"),
            AttestationError::Stale => write!(f, "state is too old (freshness check failed)"),
        }
    }
}

/// A `VehicleState` paired with an attestation signature and freshness proof.
///
/// Produced by the HAL/TEE attesting source. Only the enforcing layer (Secure Gateway)
/// calls [`verify`][Self::verify]; `decide()` never does. See ADR-0007.
///
/// Prevents **spoofing** (signature check) and **replay** (freshness check).
/// Both must pass — a valid signature on stale state is still rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedVehicleState {
    /// The vehicle state being attested.
    pub state: VehicleState,
    /// Hex-encoded ed25519 public key of the attesting source (HAL, TEE, etc.).
    pub attester_pubkey: String,
    /// Challenge nonce issued by the enforcing layer, or a monotonic counter value.
    pub nonce: String,
    /// RFC3339 timestamp at which the HAL/TEE produced this bundle.
    pub attested_at: String,
    /// Hex-encoded ed25519 signature over the SHA-256 of the attestation payload.
    pub signature: String,
}

/// Maximum age in milliseconds for timestamp-based vehicle-state freshness checks.
///
/// **Security note**: An attacker who captures a valid `{Park, 0 km/h}` state can replay
/// it for up to this many milliseconds. A value that is too large reopens the replay window;
/// a value that is too small causes spurious rejections at high enforcement-path latency.
///
/// **Provisional**: 500 ms is a discussion starting-point, not a calibrated value.
/// OEM deployments should set `freshness_ms` in [`AttestedVehicleState::verify`] based on
/// their HAL sensor-aggregator update rate and signing-path latency budget.
/// See ADR-0007 §Open Questions.
pub const ATTESTATION_FRESHNESS_MS: i64 = 500;

impl AttestedVehicleState {
    /// Sign a `VehicleState` to produce an `AttestedVehicleState`.
    ///
    /// Payload hashed: `"VEHICLE_STATE:<state_json>:<attester_pubkey_hex>:<nonce>:<attested_at>"`.
    /// Used by the HAL/TEE source, the Secure Gateway, and in tests.
    pub fn sign(
        state: VehicleState,
        signing_key: &ed25519_dalek::SigningKey,
        nonce: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        use ed25519_dalek::Signer;
        let attester_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        let attested_at = now.to_rfc3339();
        let hash = Self::payload_hash(&state, &attester_pubkey, nonce, &attested_at);
        let sig: ed25519_dalek::Signature = signing_key.sign(&hash);
        AttestedVehicleState {
            state,
            attester_pubkey,
            nonce: nonce.to_string(),
            attested_at,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify the attestation and return a [`VerifiedVehicleState`] on success.
    ///
    /// `freshness_ms`: maximum acceptable age for timestamp-based freshness checks.
    /// Pass [`ATTESTATION_FRESHNESS_MS`] for the default; OEM deployments should
    /// calibrate based on their signing-path latency budget (ADR-0007 §Open Questions).
    ///
    /// Freshness is checked via:
    /// - **Challenge–response** (`expected_nonce = Some(nonce)`): `nonce` must match exactly.
    /// - **Timestamp-based** (`expected_nonce = None`): `attested_at` must be within
    ///   `freshness_ms` of `now`.
    ///
    /// Called by the enforcing layer. `decide()` never calls this.
    pub fn verify(
        &self,
        expected_pubkey_hex: &str,
        now: chrono::DateTime<chrono::Utc>,
        freshness_ms: i64,
        expected_nonce: Option<&str>,
    ) -> Result<VerifiedVehicleState, AttestationError> {
        use ed25519_dalek::Verifier;
        if self.attester_pubkey != expected_pubkey_hex {
            return Err(AttestationError::BadSignature);
        }
        let pubkey_bytes =
            hex::decode(&self.attester_pubkey).map_err(|_| AttestationError::InvalidPubkey)?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| AttestationError::InvalidPubkey)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|_| AttestationError::InvalidPubkey)?;
        let sig_bytes = hex::decode(&self.signature).map_err(|_| AttestationError::BadSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AttestationError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let hash = Self::payload_hash(
            &self.state,
            &self.attester_pubkey,
            &self.nonce,
            &self.attested_at,
        );
        verifying_key
            .verify(&hash, &sig)
            .map_err(|_| AttestationError::BadSignature)?;
        match expected_nonce {
            Some(nonce) => {
                if self.nonce != nonce {
                    return Err(AttestationError::StaleNonce);
                }
            }
            None => {
                let attested = self
                    .attested_at
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .map_err(|_| AttestationError::Stale)?;
                let age_ms = now.signed_duration_since(attested).num_milliseconds();
                if !(0..=freshness_ms).contains(&age_ms) {
                    return Err(AttestationError::Stale);
                }
            }
        }
        Ok(VerifiedVehicleState::new(
            self.state.clone(),
            StateTrust::Attested,
        ))
    }

    fn payload_hash(
        state: &VehicleState,
        pubkey_hex: &str,
        nonce: &str,
        attested_at: &str,
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let state_json = serde_json::to_string(state).unwrap_or_default();
        let payload = format!(
            "VEHICLE_STATE:{}:{}:{}:{}",
            state_json, pubkey_hex, nonce, attested_at
        );
        Sha256::digest(payload.as_bytes()).to_vec()
    }
}

/// Verified vehicle state — proof that state has passed the attestation boundary.
///
/// Only constructable via [`AttestedVehicleState::verify`] in production code.
/// `decide()`'s Step 4.5 accepts only `Option<&VerifiedVehicleState>` — passing
/// raw `VehicleState` is a compile error. Unverified state cannot reach gating
/// by construction.
///
/// Carries a [`StateTrust`] basis so the ledger can distinguish cryptographically-attested
/// decisions from operator-typed ones (ADR-0007 follow-up).
///
/// ## Interim posture (ADR-0007 §4)
/// [`from_operator_trusted`][Self::from_operator_trusted] is an explicit escape hatch
/// for the CLI path before the Secure Gateway exists. Callers are responsible for
/// supplying accurate state on that path.
#[derive(Debug)]
pub struct VerifiedVehicleState {
    state: VehicleState,
    trust_basis: StateTrust,
}

impl VerifiedVehicleState {
    fn new(state: VehicleState, trust_basis: StateTrust) -> Self {
        VerifiedVehicleState { state, trust_basis }
    }

    /// Interim operator-trusted constructor for the CLI path (ADR-0007 §4).
    ///
    /// The operator is responsible for supplying accurate state. This constructor
    /// is expected to be replaced by [`AttestedVehicleState::verify`] once the
    /// Secure Gateway is deployed. Records `StateTrust::OperatorTrusted` in the verdict.
    pub fn from_operator_trusted(state: VehicleState) -> Self {
        VerifiedVehicleState::new(state, StateTrust::OperatorTrusted)
    }

    /// Test-only bypass — produces a `VerifiedVehicleState` without cryptographic attestation.
    #[cfg(test)]
    pub fn new_for_test(state: VehicleState) -> Self {
        VerifiedVehicleState::new(state, StateTrust::Attested)
    }

    /// Borrow the underlying `VehicleState`.
    pub fn as_vehicle_state(&self) -> &VehicleState {
        &self.state
    }

    /// The trust basis recorded for this state.
    pub fn trust_basis(&self) -> StateTrust {
        self.trust_basis
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::panic
)]
mod tests {
    use super::*;

    // ── Classification: vehicle.* strings (unchanged from PR #7) ─────────────

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

    // ── Classification: VHAL property names ──────────────────────────────────

    #[test]
    fn test_classify_vhal_comfort() {
        // HVAC write → Comfort
        assert_eq!(
            classify_vehicle_tool("HVAC_TEMPERATURE_SET"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("HVAC_FAN_SPEED"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("HVAC_DEFROSTER"),
            VehicleDomain::Comfort
        );
        // Seat heating → Comfort (via HVAC_SEAT_TEMPERATURE)
        assert_eq!(
            classify_vehicle_tool("HVAC_SEAT_TEMPERATURE"),
            VehicleDomain::Comfort
        );
        // Seat movement write → Comfort
        assert_eq!(
            classify_vehicle_tool("SEAT_MEMORY_SELECT"),
            VehicleDomain::Comfort
        );
        // Lighting write → Comfort
        assert_eq!(
            classify_vehicle_tool("CABIN_LIGHTS_SWITCH"),
            VehicleDomain::Comfort
        );
        assert_eq!(
            classify_vehicle_tool("DISPLAY_BRIGHTNESS"),
            VehicleDomain::Comfort
        );
    }

    #[test]
    fn test_classify_vhal_sensitive() {
        assert_eq!(
            classify_vehicle_tool("WINDOW_POS"),
            VehicleDomain::Sensitive
        );
        assert_eq!(
            classify_vehicle_tool("WINDOW_MOVE"),
            VehicleDomain::Sensitive
        );
        assert_eq!(classify_vehicle_tool("DOOR_LOCK"), VehicleDomain::Sensitive);
        assert_eq!(classify_vehicle_tool("DOOR_MOVE"), VehicleDomain::Sensitive);
        assert_eq!(
            classify_vehicle_tool("EV_CHARGE_PORT_OPEN"),
            VehicleDomain::Sensitive
        );
    }

    #[test]
    fn test_classify_vhal_forbidden() {
        // ADAS write → Forbidden
        assert_eq!(
            classify_vehicle_tool("CRUISE_CONTROL_COMMAND"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("LANE_CENTERING_ASSIST_COMMAND"),
            VehicleDomain::Forbidden
        );
        // Chassis/propulsion write → Forbidden
        assert_eq!(
            classify_vehicle_tool("ELECTRONIC_STABILITY_CONTROL_ENABLED"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("EV_STOPPING_MODE"),
            VehicleDomain::Forbidden
        );
        assert_eq!(
            classify_vehicle_tool("EV_CHARGE_CURRENT_DRAW_LIMIT"),
            VehicleDomain::Forbidden
        );
    }

    #[test]
    fn test_classify_vhal_read_only_non_vehicle() {
        // Read-only telemetry (state sources) → NonVehicle; never forbidden,
        // never gated — the agent may observe these but not act through them.
        assert_eq!(
            classify_vehicle_tool("PERF_VEHICLE_SPEED"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("PERF_VEHICLE_SPEED_DISPLAY"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("GEAR_SELECTION"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("CURRENT_GEAR"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("ENGINE_RPM"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("IGNITION_STATE"),
            VehicleDomain::NonVehicle
        );
        // Read-only telemetry even when domain is conceptually Comfort
        assert_eq!(
            classify_vehicle_tool("HVAC_TEMPERATURE_CURRENT"),
            VehicleDomain::NonVehicle
        );
        assert_eq!(
            classify_vehicle_tool("CABIN_LIGHTS_STATE"),
            VehicleDomain::NonVehicle
        );
    }

    #[test]
    fn test_classify_vhal_unknown_non_vehicle() {
        // Unknown VHAL names (not in table, not vehicle.*) → NonVehicle
        assert_eq!(
            classify_vehicle_tool("SOME_OEM_CUSTOM_PROP"),
            VehicleDomain::NonVehicle
        );
    }

    // ── State evaluation ─────────────────────────────────────────────────────

    #[test]
    fn test_parked_stopped_allows_sensitive() {
        let state = VehicleState {
            speed_mmps: 0,
            gear: Gear::Park,
            actor: Actor::Driver,
        };
        assert!(state.is_parked_and_stopped());
        assert_eq!(
            evaluate_vehicle_state("vehicle.window.open", &state),
            StateVerdict::Allow
        );
        assert_eq!(
            evaluate_vehicle_state("DOOR_LOCK", &state),
            StateVerdict::Allow
        );
    }

    #[test]
    fn test_moving_denies_sensitive() {
        let state = VehicleState {
            speed_mmps: 8_333, // 30.0 km/h
            gear: Gear::Drive,
            actor: Actor::Driver,
        };
        let v = evaluate_vehicle_state("WINDOW_POS", &state);
        match v {
            StateVerdict::Deny(r) => assert!(r.contains("vehicle_state_violation")),
            StateVerdict::Allow => panic!("expected Deny for moving vehicle"),
        }
    }

    #[test]
    fn test_speed_below_threshold_but_not_park_denies() {
        let state = VehicleState {
            speed_mmps: 833,   // 3.0 km/h
            gear: Gear::Drive, // still in Drive
            actor: Actor::Passenger,
        };
        assert_eq!(
            evaluate_vehicle_state("vehicle.door.unlock", &state),
            StateVerdict::Deny(
                "vehicle_state_violation: sensitive capabilities (window/door/trunk/lock) \
                 require speed_mmps < 1389 (< 5.0 km/h) and gear == Park"
            )
        );
    }

    #[test]
    fn test_park_gear_high_speed_denies() {
        // Physically impossible, but the engine must be fail-safe.
        let state = VehicleState {
            speed_mmps: 16_667, // 60.0 km/h
            gear: Gear::Park,
            actor: Actor::Driver,
        };
        assert!(!state.is_parked_and_stopped());
        assert!(matches!(
            evaluate_vehicle_state("WINDOW_POS", &state),
            StateVerdict::Deny(_)
        ));
    }

    #[test]
    fn test_fail_safe_default_denies_sensitive() {
        let params = serde_json::json!({}); // no vehicle_state
        let state = extract_vehicle_state(&params);
        assert!(state.speed_mmps >= SPEED_GATE_MMPS);
        assert_eq!(state.gear, Gear::Drive);
        assert!(matches!(
            evaluate_vehicle_state("WINDOW_POS", &state),
            StateVerdict::Deny(_)
        ));
    }

    #[test]
    fn test_extract_valid_state() {
        let params = serde_json::json!({
            "vehicle_state": {"speed_mmps": 0, "gear": "Park", "actor": "Passenger"}
        });
        let state = extract_vehicle_state(&params);
        assert_eq!(state.gear, Gear::Park);
        assert_eq!(state.actor, Actor::Passenger);
        assert!(state.is_parked_and_stopped());
    }
}
