# ADR-0006: AAOS VHAL Property Mapping

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `feat/aaos-vhal-mapping`

---

## Context

ADR-0005 introduced the four-domain vehicle capability model using generic
`vehicle.<domain>.<action>` strings (e.g. `vehicle.climate.set_temperature`,
`vehicle.door.unlock`). These strings are clear to a software engineer but are
not recognisable to an automotive engineer who works with the Android Automotive
OS (AAOS) Vehicle Hardware Abstraction Layer (VHAL).

AAOS exposes the vehicle sub-system to applications through
`android.hardware.automotive.vehicle.VehicleProperty` constants with well-known
symbolic names (`HVAC_TEMPERATURE_SET`, `DOOR_LOCK`, `PERF_VEHICLE_SPEED`, …).
An in-cabin agent ultimately wants to act on these properties. Making the A2G
capability model speak the same language as the VHAL surface is necessary for:

1. **OEM adoption** — mandate authors and reviewers can reference the AAOS
   developer documentation directly; no translation step.
2. **Safety audit** — security reviewers can compare the A2G Forbidden list
   against the AAOS `VehicleProperty` enumeration to verify completeness.
3. **Runtime integration** — an A2G mediator process that wraps the AAOS VHAL
   can pass symbolic property names as the `tool` argument to `decide()`
   without a pre-processing translation layer.

## Decision

### 1. VHAL Property Mapping Table

A static table `VHAL_PROPERTIES: &[VhalPropertyMapping]` is added to
`crates/a2g-core/src/vehicle.rs`. Each entry records:

- `name: &'static str` — AAOS `VehicleProperty` symbolic name
- `access: VhalAccessMode` — `Read`, `Write`, or `ReadWrite`
- `domain: VehicleDomain` — conceptual A2G domain for documentation
- `description: &'static str` — one-line description

The table is a `&[…]` static slice (no heap allocation, no HashMap); 36 entries
cover HVAC, seat, lighting, display, navigation, windows, doors, charge port,
telemetry, and safety-critical ADAS/propulsion/chassis properties.

### 2. Access-Mode Classification Rule

The forbidden rule is specifically about **write access** to safety-critical
systems. A read-only property (`access == Read`) is a telemetry source, not an
agent-initiated command, and must not be subject to Forbidden or Sensitive
classification — an agent observing vehicle speed is not the same as an agent
commanding propulsion.

```
if property.access == Read:
    effective_domain = NonVehicle
else:
    effective_domain = property.domain
```

This rule is implemented in `classify_vhal_property()`.  
Consequence: `PERF_VEHICLE_SPEED` (Read) → NonVehicle → always ALLOW when
listed in a mandate. `CRUISE_CONTROL_COMMAND` (Write) → Forbidden → hard DENY
regardless of mandate contents.

### 3. Dual-Form `classify_vehicle_tool()`

`classify_vehicle_tool(tool: &str)` is updated to accept both forms:

```
if tool.starts_with("vehicle."):
    // prefix-based matching — unchanged from PR #7
else:
    classify_vhal_property(tool)  // VHAL table lookup
```

The `vehicle.*` path is unchanged; no existing mandate, test, or call site is
affected. VHAL property names are a purely additive second form.

### 4. A2G as VHAL Mediator

The agent **never** calls VHAL directly. A2G governance is the mandatory
intermediary:

```
Agent → A2G decide() → VHAL
```

The A2G mediator process (CLI or embedded runtime) receives a VHAL property
name as the `tool` parameter, calls `decide()`, and only forwards the command
to the VHAL HAL on `Decision::Allow`. On `Decision::Deny` or
`Decision::Escalate`, the command is blocked and the agent is notified. This
separation ensures that no mandate permission, however permissive, can reach
a Forbidden property — the pre-check in `decide()` fires unconditionally before
any mandate field is consulted.

### 5. VehicleState VHAL Field Documentation

`VehicleState` doc comments are updated to cross-reference the AAOS properties
that feed each field at runtime:

| Field | AAOS property | Notes |
|---|---|---|
| `speed_kph` | `PERF_VEHICLE_SPEED` (0x11600207) | AAOS reports m/s; convert to km/h |
| `gear` | `GEAR_SELECTION` (0x11400400) | `GEAR_PARK`=0x04, `GEAR_DRIVE`=0x20 |
| `actor` | Active UX session zone | Driver vs. Passenger |

### 6. Example Mandate Updated

`examples/in-cabin-assistant.mandate.toml` is updated to use VHAL property
names with per-entry comments (VehicleProperty ID, domain, description).
The file is the canonical demonstration of how to author a mandate for an
AAOS-integrated agent.

### 7. no_std Compatibility

The VHAL mapping layer introduces no new no_std blockers:
- `VHAL_PROPERTIES` is a `&'static [VhalPropertyMapping]` with `&'static str`
  fields — no heap allocation.
- `classify_vhal_property()` is a linear scan over 36 entries — O(n) on the
  hot path but stack-only and cache-friendly.
- `VhalAccessMode` and `VhalPropertyMapping` are plain Rust types with no
  `std` dependencies.

The existing no_std blockers (Box<dyn Error>, toml, regex, uuid, Mutex) are
unchanged. See `docs/no_std-blockers.md`.

## Consequences

### Positive

- Mandate authors can copy AAOS VehicleProperty names directly; no translation
  needed between VHAL documentation and A2G mandate authoring.
- Safety reviewers can audit the Forbidden list against the AAOS VHAL spec.
- An AAOS mediator can pass VHAL property names to `decide()` without
  preprocessing.
- Read-only telemetry (speed, gear, ignition) is explicitly represented and
  always permitted — no accidental denial of state-observation tools.
- All existing `vehicle.*` mandates and tests continue to work unchanged.

### Neutral

- Linear scan over 36 entries is O(n) per `classify_vehicle_tool()` call for
  VHAL names. For the expected call rate (tens of calls per second) this is
  negligible. A sorted array + binary search or a perfect hash could be added
  later if profiling justifies it.
- The VHAL property table is hardcoded in source, consistent with the
  rationale for the hardcoded forbidden list in ADR-0005.

### Negative

- The VHAL property table is a snapshot; new AAOS VehicleProperty constants
  introduced in future Android versions must be added manually. Unknown VHAL
  names fall through to NonVehicle (permissive default for unknown names),
  which means a newly introduced safety-critical property would not be
  Forbidden until explicitly added. **Mitigation:** the Forbidden pre-check
  also applies to `vehicle.*` prefix strings, so OEM-specific forbidden tools
  can use the `vehicle.forbidden.*` convention as a stopgap.

## Alternatives Considered

| Alternative | Rejected because |
|---|---|
| Runtime VHAL property registry (config file or database) | Adds I/O and a trust input; the static table is auditable in source. Consistent with the decision to hardcode the Forbidden list (ADR-0005 §Deferred). |
| JNI / Android SDK dependency in `a2g-core` | Contradicts the no_std / pure-Rust mandate. A2G core must be portable; AAOS integration belongs in the CLI or a separate mediator crate. |
| Integer VHAL property IDs instead of symbolic names | Integer IDs are not human-readable in mandates; symbolic names are self-documenting and match AAOS developer documentation. |
| Separate `a2g-aaos` crate | Premature. The mapping layer is small (36 entries, ~200 LOC) and belongs in `vehicle.rs` alongside the domain model it extends. A separate crate makes sense once OEM-specific overrides or a richer VHAL surface are needed. |

## Open Questions

### Completeness of the Forbidden List

The current table covers the ADAS, propulsion, and chassis-safety properties
most likely to be targeted by an overly permissive mandate. It does not cover
every AAOS VehicleProperty that could be considered safety-relevant (e.g.
`TIRE_PRESSURE_DISPLAY_UNITS`, `FUEL_DOOR_OPEN`). The current approach is
conservative: only write operations on unambiguously safety-critical properties
are forbidden; the rest are gated by domain classification and mandate
contents.

If a more comprehensive Forbidden list is needed, it should be proposed as an
update to this ADR with justification for each addition.

### Per-OEM Property Extensions

AAOS allows OEMs to define custom VehicleProperty IDs in the vendor range
(0x20000000–0x3FFFFFFF). These cannot be represented in the current static
table. When OEM-specific capabilities are needed, the recommended approach is
to use the `vehicle.<domain>.<action>` string form with an OEM-specific
sub-domain prefix (e.g. `vehicle.oem_comfort.massage_seat`), which will
classify as Sensitive or Comfort depending on the sub-domain prefix.

## References

- ADR-0005: Vehicle Capability Model — `docs/adr/0005-vehicle-capability-model.md`
- Mapping table: `docs/aaos-vhal-mapping.md`
- Implementation: `crates/a2g-core/src/vehicle.rs`
- Example mandate: `examples/in-cabin-assistant.mandate.toml`
- no_std blockers: `docs/no_std-blockers.md`
- AAOS VHAL HAL definition: `android.hardware.automotive.vehicle.VehicleProperty` (AOSP)
