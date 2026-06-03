# AAOS VHAL Property ID Verification

Verification status for every entry originally in `VHAL_PROPERTIES`
(`crates/a2g-core/src/vehicle.rs`) and `docs/aaos-vhal-mapping.md`.

**Sources consulted:**
- `packages/services/Car/car-lib/src/android/car/VehiclePropertyIds.java` (AOSP master)
- `hardware/interfaces/automotive/vehicle/2.0/types.hal` (AOSP HIDL definitions)
- Structural encoding: `VehiclePropertyGroup | VehicleArea | VehiclePropertyType | unique_id`

**Encoding reference:**

| Component | Values |
|---|---|
| Group | SYSTEM = 0x10000000 |
| Area | GLOBAL = 0x01000000, WINDOW = 0x03000000, SEAT = 0x05000000, DOOR = 0x06000000 |
| Type | BOOLEAN = 0x00200000, INT32 = 0x00400000, FLOAT = 0x00600000 |

**Status key:**

| Status | Meaning |
|---|---|
| CORRECT | As-shipped ID matches authoritative source |
| CORRECTED | ID was wrong; corrected to verified value |
| RENAMED | Property name not in AAOS VHAL; replaced with canonical name |
| REMOVED | Property name not in AAOS VHAL; no direct canonical equivalent; entry dropped |

---

## Comfort — HVAC

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `HVAC_TEMPERATURE_SET` | 0x15600503 | 0x15600503 | **CORRECT** | Confirmed via `VehiclePropertyIds.java` decimal 358614275 |
| `HVAC_FAN_SPEED` | 0x15600500 | 0x15400500 | **CORRECTED** | Type encoded as FLOAT (0x6); should be INT32 (0x4); SEAT area correct |
| `HVAC_FAN_DIRECTION` | 0x15600501 | 0x15400501 | **CORRECTED** | Same FLOAT→INT32 type error as `HVAC_FAN_SPEED` |
| `HVAC_POWER_ON` | 0x15200510 | 0x15200510 | **CORRECT** | SEAT, BOOLEAN, unique ID 0x510 matches `types.hal` |
| `HVAC_DEFROSTER` | 0x15200511 | 0x13200504 | **CORRECTED** | Area wrong (SEAT 0x05 → WINDOW 0x03); unique ID wrong (0x511 → 0x504) |
| `HVAC_AUTO_ON` | 0x15200512 | 0x1520050A | **CORRECTED** | Unique ID wrong (0x512 → 0x50A) |
| `HVAC_TEMPERATURE_CURRENT` | 0x15600502 | 0x15600502 | **CORRECT** | Read-only; SEAT, FLOAT |
| `SEAT_TEMP` | 0x15400B90 | → `HVAC_SEAT_TEMPERATURE` 0x1540050B | **RENAMED** | `SEAT_TEMP` not in AAOS VHAL; canonical name is `HVAC_SEAT_TEMPERATURE` (SEAT, INT32, 0x50B) |

## Comfort — Seat Adjustment

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `SEAT_MEMORY_SELECT` | 0x15400F90 | 0x15400B80 | **CORRECTED** | Unique ID wrong (0xF90 → 0xB80) |
| `SEAT_FORE_AFT_MOVE` | 0x15400B87 | 0x15400B86 | **CORRECTED** | Off-by-one; 0xB87 = `SEAT_BACK_TILT_POS` |
| `SEAT_HEIGHT_MOVE` | 0x15400B8B | 0x15400B8C | **CORRECTED** | Off-by-one; 0xB8B = `SEAT_HEIGHT_POS` |
| `SEAT_BACK_RECLINE_ANGLE_ABS_POS` | 0x15400B89 | — | **REMOVED** | Name not in AAOS VHAL; 0xB89 = `SEAT_LUMBAR_FORE_AFT_POS` |
| `SEAT_LUMBAR_FORE_AFT_MOVE` | 0x15400B8F | 0x15400B92 | **CORRECTED** | Unique ID wrong (0xB8F → 0xB92) |
| `SEAT_HEADREST_ANGLE_MOVE` | 0x15400B95 | 0x15400B98 | **CORRECTED** | Unique ID wrong (0xB95 → 0xB98) |

## Comfort — Cabin Lighting

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `CABIN_LIGHTS_SWITCH` | 0x11400F82 | 0x11400F02 | **CORRECTED** | Unique ID wrong (0xF82 → 0xF02) |
| `CABIN_LIGHTS_STATE` | 0x11400F81 | 0x11400F01 | **CORRECTED** | Unique ID wrong (0xF81 → 0xF01); read-only telemetry |
| `READING_LIGHTS_SWITCH` | 0x15400F85 | 0x15400F04 | **CORRECTED** | Unique ID wrong (0xF85 → 0xF04) |
| `DISPLAY_BRIGHTNESS` | 0x11400F1B | 0x11400A03 | **CORRECTED** | Unique ID wrong (0xF1B → 0xA03) |

## Convenience

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `INFO_DRIVING_STATUS` | 0x11400F25 | — | **REMOVED** | Name not in AAOS VHAL; use `vehicle.navigation.*` prefix form |
| `NAV_VOLUME_GROUP_COMMAND` | 0x11400F36 | — | **REMOVED** | Name not in AAOS VHAL; use `vehicle.navigation.*` prefix form |

## Sensitive — Windows

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `WINDOW_POS` | 0x13400BC0 | 0x13400BC0 | **CORRECT** | WINDOW area, INT32 |
| `WINDOW_MOVE` | 0x13400BC1 | 0x13400BC1 | **CORRECT** | WINDOW area, INT32 |

## Sensitive — Doors and Charge Port

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `DOOR_LOCK` | 0x16400F01 | 0x16200B02 | **CORRECTED** | Type wrong (INT32 → BOOLEAN); unique ID wrong (0xF01 → 0xB02) |
| `DOOR_MOVE` | 0x16400BD2 | 0x16400B01 | **CORRECTED** | Unique ID wrong (0xBD2 → 0xB01) |
| `EV_CHARGE_PORT_OPEN` | 0x11200EF8 | 0x1120030A | **CORRECTED** | Unique ID wrong (0xEF8 → 0x30A) |

## Telemetry (Read-Only)

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `PERF_VEHICLE_SPEED` | 0x11600207 | 0x11600207 | **CORRECT** | Confirmed via `VehiclePropertyIds.java` decimal 291504647 |
| `PERF_VEHICLE_SPEED_DISPLAY` | 0x11600208 | 0x11600208 | **CORRECT** | GLOBAL, FLOAT |
| `GEAR_SELECTION` | 0x11400400 | 0x11400400 | **CORRECT** | Confirmed via `VehiclePropertyIds.java` decimal 289408000 |
| `CURRENT_GEAR` | 0x11400401 | 0x11400401 | **CORRECT** | GLOBAL, INT32 |
| `ENGINE_RPM` | 0x11600115 | 0x11600305 | **CORRECTED** | Unique ID wrong (0x115 → 0x305); 0x115 is unassigned |
| `IGNITION_STATE` | 0x11400409 | 0x11400409 | **CORRECT** | GLOBAL, INT32 |

## Forbidden

| Property | As-Shipped ID | Verified ID | Status | Notes |
|---|---|---|---|---|
| `CRUISE_CONTROL_COMMAND` | 0x15400456 | 0x11401012 | **CORRECTED** | Area wrong (SEAT → GLOBAL); unique ID wrong (0x456 → 0x1012) |
| `LANE_CENTERING_ASSIST_COMMAND` | 0x15400467 | 0x1140100B | **CORRECTED** | Area wrong (SEAT → GLOBAL); unique ID wrong (0x467 → 0x100B) |
| `HANDS_ON_DETECTION_ENABLED` | 0x11200471 | 0x11201016 | **CORRECTED** | Unique ID wrong (0x471 → 0x1016) |
| `ELECTRONIC_STABILITY_CONTROLS` | 0x11400407 | → `ELECTRONIC_STABILITY_CONTROL_ENABLED` 0x1120040E | **RENAMED** | Name not in AAOS VHAL; type also wrong (INT32 → BOOLEAN) |
| `EV_STOPPING_MODE` | 0x11400472 | 0x1140040D | **CORRECTED** | Unique ID wrong (0x472 → 0x40D) |
| `EV_CHARGE_CURRENT_DRAW_LIMIT` | 0x1540040C | 0x11600F3F | **CORRECTED** | Area wrong (SEAT → GLOBAL); type wrong (INT32 → FLOAT) |

---

## Summary

| Status | Count |
|---|---|
| CORRECT | 10 |
| CORRECTED (ID fixed) | 22 |
| RENAMED (name + ID fixed) | 2 |
| REMOVED (no AAOS equivalent) | 3 |
| **Total as-shipped** | **37** |
| **Total after verification** | **34** |

Of the 37 entries originally shipped: 10 were correct, 22 had wrong hex IDs (all
corrected), 2 had non-existent names (renamed to canonical AAOS equivalents), and
3 had non-existent names with no direct AAOS equivalent (removed). No domain
classifications or gating logic were changed.
