# AAOS VHAL Property → A2G Capability Domain Mapping

This document maps Android Automotive OS (AAOS)
`android.hardware.automotive.vehicle.VehicleProperty` symbolic names to the
A2G four-domain capability model (ADR-0005, ADR-0006).

## A2G as VHAL Mediator

The A2G governance engine sits between an in-cabin AI agent and the vehicle's
VHAL surface. The agent never calls `VehicleProperty` APIs directly; every
proposed action is submitted to A2G's `decide()` pipeline first.

```
 In-Cabin Agent
       │
       │  tool = "HVAC_TEMPERATURE_SET", params = {...}
       ▼
 ┌─────────────────────────────────────────────────────┐
 │              A2G Governance Engine                  │
 │  Pre-check: Forbidden domain → hard DENY            │
 │  Step 3:    Mandate tool authorisation              │
 │  Step 4.5:  Sensitive state gating (Park + stopped) │
 │  Step 6:    Escalation (human-in-the-loop)          │
 └─────────────────────────────────────────────────────┘
       │
       │  Verdict: ALLOW / DENY / ESCALATE
       ▼
  VHAL / Vehicle sub-system
```

The four-domain taxonomy and all verdict logic are defined in ADR-0005 and
implemented in `crates/a2g-core/src/vehicle.rs`. This document covers the
AAOS-specific naming layer (ADR-0006).

---

## Property Mapping Table

VHAL integer IDs are shown for cross-reference only; A2G uses symbolic names.
`Access` reflects the AAOS property access mode.  
`Effective domain` is the A2G domain after applying the access-mode rule:
`Read`-only entries always resolve to **NonVehicle** (telemetry, not commands).

### Comfort — HVAC

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `HVAC_TEMPERATURE_SET` | 0x15600503 | ReadWrite | Comfort | Set per-zone cabin target temperature |
| `HVAC_FAN_SPEED` | 0x15600500 | ReadWrite | Comfort | Set HVAC fan speed level |
| `HVAC_FAN_DIRECTION` | 0x15600501 | ReadWrite | Comfort | Set HVAC airflow direction |
| `HVAC_POWER_ON` | 0x15200510 | ReadWrite | Comfort | Toggle HVAC system power |
| `HVAC_DEFROSTER` | 0x15200511 | ReadWrite | Comfort | Toggle front/rear defroster |
| `HVAC_AUTO_ON` | 0x15200512 | ReadWrite | Comfort | Toggle HVAC automatic mode |
| `HVAC_TEMPERATURE_CURRENT` | 0x15600502 | **Read** | **NonVehicle** | Read current cabin temperature (telemetry) |

### Comfort — Seat Adjustment

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `SEAT_MEMORY_SELECT` | 0x15400F90 | Write | Comfort | Recall a stored seat memory preset |
| `SEAT_FORE_AFT_MOVE` | 0x15400B87 | Write | Comfort | Move seat forward or rearward |
| `SEAT_HEIGHT_MOVE` | 0x15400B8B | Write | Comfort | Raise or lower seat height |
| `SEAT_BACK_RECLINE_ANGLE_ABS_POS` | 0x15400B89 | ReadWrite | Comfort | Set seatback recline angle |
| `SEAT_LUMBAR_FORE_AFT_MOVE` | 0x15400B8F | Write | Comfort | Adjust lumbar support depth |
| `SEAT_HEADREST_ANGLE_MOVE` | 0x15400B95 | Write | Comfort | Adjust headrest angle |
| `SEAT_TEMP` | 0x15400B90 | ReadWrite | Comfort | Set seat heating or cooling level |

### Comfort — Cabin Lighting

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `CABIN_LIGHTS_SWITCH` | 0x11400F82 | ReadWrite | Comfort | Control cabin interior light switch state |
| `CABIN_LIGHTS_STATE` | 0x11400F81 | **Read** | **NonVehicle** | Read cabin light state (telemetry) |
| `READING_LIGHTS_SWITCH` | 0x15400F85 | ReadWrite | Comfort | Toggle per-zone reading lights |
| `DISPLAY_BRIGHTNESS` | 0x11400F1B | ReadWrite | Comfort | Set infotainment display brightness |

### Convenience

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `INFO_DRIVING_STATUS` | 0x11400F25 | **Read** | **NonVehicle** | Read UX restriction / driving-status mask (telemetry) |
| `NAV_VOLUME_GROUP_COMMAND` | 0x11400F36 | Write | Convenience | Command navigation audio volume group |

### Sensitive — Windows

State gating applies: speed < 5 km/h **and** gear == Park required.
Default verdict is ESCALATE (human-in-the-loop); state violation fires first.

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `WINDOW_POS` | 0x13400BC0 | ReadWrite | Sensitive | Set window absolute position (0 = closed) |
| `WINDOW_MOVE` | 0x13400BC1 | Write | Sensitive | Command continuous window movement |

### Sensitive — Doors and Charge Port

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `DOOR_LOCK` | 0x16400F01 | ReadWrite | Sensitive | Lock or unlock a door |
| `DOOR_MOVE` | 0x16400BD2 | Write | Sensitive | Command powered door open/close movement |
| `EV_CHARGE_PORT_OPEN` | 0x11200EF8 | ReadWrite | Sensitive | Open or close EV charge port door |

### Telemetry (Read-Only → NonVehicle)

These properties feed `VehicleState` for gating decisions.  
Reading them is **always permitted** (never Forbidden, never state-gated).  
The agent may observe vehicle state but cannot command through read-only properties.

| VHAL Property | VHAL ID | Access | Maps to | Description |
|---|---|---|---|---|
| `PERF_VEHICLE_SPEED` | 0x11600207 | **Read** | `VehicleState::speed_kph` (convert m/s → km/h) | Current vehicle speed |
| `PERF_VEHICLE_SPEED_DISPLAY` | 0x11600208 | **Read** | — | Display-filtered (speedometer) speed |
| `GEAR_SELECTION` | 0x11400400 | **Read** | `VehicleState::gear` | Selected gear position |
| `CURRENT_GEAR` | 0x11400401 | **Read** | `VehicleState::gear` | Currently engaged gear (may differ during shift) |
| `ENGINE_RPM` | 0x11600115 | **Read** | — | Engine RPM |
| `IGNITION_STATE` | 0x11400409 | **Read** | — | Ignition / engine-running state |

### Forbidden — ADAS, Propulsion, Chassis Safety (Hard DENY)

These properties control safety-critical systems.
**Write access is unconditionally denied** — no mandate permission, escalation grant,
or vehicle state can override this. The check fires before mandate evaluation.

| VHAL Property | VHAL ID | Access | Effective Domain | Description |
|---|---|---|---|---|
| `CRUISE_CONTROL_COMMAND` | 0x15400456 | Write | **Forbidden** | Adaptive cruise-control command (ADAS write) |
| `LANE_CENTERING_ASSIST_COMMAND` | 0x15400467 | Write | **Forbidden** | Lane-centering assist command (ADAS write) |
| `HANDS_ON_DETECTION_ENABLED` | 0x11200471 | ReadWrite | **Forbidden** | Enable/disable hands-on detection (ADAS safety) |
| `ELECTRONIC_STABILITY_CONTROLS` | 0x11400407 | ReadWrite | **Forbidden** | Enable/disable ESC (chassis safety) |
| `EV_STOPPING_MODE` | 0x11400472 | ReadWrite | **Forbidden** | Set one-pedal / creep regen mode (propulsion) |
| `EV_CHARGE_CURRENT_DRAW_LIMIT` | 0x1540040C | ReadWrite | **Forbidden** | Override max charge current draw (propulsion) |

---

## Access-Mode Classification Rule

```
if property.access == Read:
    effective_domain = NonVehicle   # state observation, not a command
else:
    effective_domain = property.domain  # Write or ReadWrite uses the mapped domain
```

This rule is implemented in `classify_vhal_property()` in `vehicle.rs` and
ensures that read-only telemetry properties are never subject to the Sensitive
state-gate or the Forbidden hard-deny, regardless of their conceptual tier.

---

## Backward Compatibility

`vehicle.<domain>.<action>` strings (PR #7 / ADR-0005) continue to classify
correctly via prefix matching in `classify_vehicle_tool()`. The VHAL name
lookup is an additive second form — no existing mandate or test is affected.

---

## VehicleState Field Mapping

`VehicleState` used in Step 4.5 state gating maps directly to AAOS properties:

| `VehicleState` field | AAOS property | Notes |
|---|---|---|
| `speed_kph` | `PERF_VEHICLE_SPEED` (0x11600207) | AAOS reports m/s; callers convert to km/h |
| `gear` | `GEAR_SELECTION` (0x11400400) | `Park`=0x04, `Reverse`=0x08, `Neutral`=0x10, `Drive`=0x20 |
| `actor` | Derived from active UX zone | Driver vs. Passenger seat |

---

## References

- ADR-0005: Vehicle Capability Model — `docs/adr/0005-vehicle-capability-model.md`
- ADR-0006: AAOS VHAL Mapping — `docs/adr/0006-aaos-vhal-mapping.md`
- Implementation: `crates/a2g-core/src/vehicle.rs`
- Example mandate: `examples/in-cabin-assistant.mandate.toml`
- AAOS VHAL HAL definition: `android.hardware.automotive.vehicle.VehicleProperty` (AOSP)
