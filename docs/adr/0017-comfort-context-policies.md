# ADR-0017: Context-Aware Comfort Policies

**Status:** Accepted  
**Date:** 2026-06-11  
**Supersedes:** —  
**Superseded by:** —  
**Related:** ADR-0005 (vehicle capability model), ADR-0016 (gateway state ingestion)

---

## Context

Prior to this ADR the Comfort domain was unconditionally `ALLOW` regardless of
vehicle speed or context.  This was correct for most Comfort capabilities
(HVAC, lighting, media playback) which present no safety hazard at any speed.

However, a subset of Comfort tools — seat-position adjustments — can be
distracting or even dangerous when performed at higher speeds.  A forward/rearward
seat move while the driver is traveling at highway speed requires them to
re-establish their driving position, potentially releasing the steering wheel
and losing situational awareness.

## Decision

The `decide()` function applies a **context-aware comfort gate** for
seat-position adjustment tools when vehicle state is available:

| Condition | Gate | Result |
|-----------|------|--------|
| Tool is a seat-position tool AND `speed_mmps ≥ COMFORT_SEAT_SPEED_GATE_MMPS` (≥ 30 km/h) | Speed gate | `DENY comfort_context_violation` |
| Tool is a seat-position tool AND `speed_mmps < COMFORT_SEAT_SPEED_GATE_MMPS` (< 30 km/h) | — | `ALLOW` |
| Tool is any other Comfort tool | — | `ALLOW` |
| No vehicle state supplied | — | `ALLOW` (Comfort safe by omission) |

### Seat-position tools subject to the gate

- `SEAT_FORE_AFT_MOVE` — fore/aft movement
- `SEAT_HEIGHT_MOVE` — height adjustment
- `SEAT_LUMBAR_FORE_AFT_MOVE` — lumbar depth
- `SEAT_HEADREST_ANGLE_MOVE` — headrest angle
- `vehicle.seat.fore_aft`, `vehicle.seat.height`, `vehicle.seat.lumbar`, `vehicle.seat.headrest`
  (internal path-form aliases)

### Implementation

`evaluate_comfort_state(tool, state)` in `a2g_core::vehicle` is a pure,
deterministic function with no allocation on the `Allow` path.

In `decide()` (enforce.rs), after the Sensitive gate and before the jurisdiction
check, the Comfort gate is evaluated:

```rust
if tool_domain == VehicleDomain::Comfort {
    if let Some(vs) = verified_state {
        if let StateVerdict::Deny(reason) = evaluate_comfort_state(tool, vs.as_vehicle_state()) {
            return Deny(reason);
        }
    }
    // No state → ALLOW (Comfort is safe by omission)
}
```

### Speed threshold

`COMFORT_SEAT_SPEED_GATE_MMPS = 8_333 mm/s` (exactly 30 km/h × 1 000 000 ÷ 3 600,
rounded to nearest integer).  The threshold is a named constant so OEM deployments
can adjust it without modifying the evaluation logic.

## Consequences

**Positive:**
- Eliminates a driver-distraction hazard: an AI agent cannot autonomously adjust
  the driver's seat position at highway speed.
- Pure, deterministic gate — no new I/O, no clock dependency, no heap allocation.
- Backward-compatible: HVAC, cabin lighting, and media remain unconditionally ALLOW.
- The 30 km/h threshold is well below highway speeds but allows adjustment in
  parking lots and slow traffic.

**Negative / trade-offs:**
- A passenger requesting their own seat adjustment while the vehicle is moving
  at 35 km/h is also blocked.  This is a deliberate conservative choice; OEMs
  may set a higher threshold or add an `Actor::Passenger` bypass in future.
- Requires vehicle state to be supplied to exercise the gate; if state is absent
  the gate does not fire (Comfort safe by omission).  For Comfort this is
  acceptable — unlike Sensitive tools where the absence of state must be
  fail-dangerous.

## References

- `crates/a2g-core/src/vehicle.rs` — `evaluate_comfort_state()`,
  `COMFORT_SEAT_SPEED_GATE_MMPS`, `is_comfort_seat_tool()`
- `crates/a2g-core/src/enforce.rs` — integration in `decide()`
- ADR-0005 (capability model), ADR-0016 (gateway state feeds `verified_state`)
