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

The `decide()` function applies an **actor-zone-keyed comfort gate** for
seat-position adjustment tools when vehicle state is available:

| Actor | Condition | Gate | Result |
|-------|-----------|------|--------|
| `Driver` | Seat tool AND `speed_mmps ≥ SPEED_GATE_MMPS` (≥ 5 km/h) | Motion gate | `DENY comfort_context_violation` |
| `Driver` | Seat tool AND `speed_mmps < SPEED_GATE_MMPS` (< 5 km/h) | — | `ALLOW` |
| `Passenger` | Seat tool (any speed) | — | `ALLOW` |
| Any | Non-seat Comfort tool | — | `ALLOW` |
| Any | No vehicle state supplied | — | `ALLOW` (Comfort safe by omission) |

The driver-zone gate fires at essentially any motion (≥ 5 km/h).  Passenger-zone
seat adjustments are unconditionally permissive — a passenger legitimately adjusts
their seat at highway speed.

### Seat-position tools subject to the driver-zone gate

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

`SPEED_GATE_MMPS = 1_389 mm/s` (5 km/h, shared with the Sensitive domain gate).
Driver-zone seat adjustments are blocked at essentially any vehicle motion.

### Known limitation

This gate is evaluated inside `decide()` on the rich-domain path.  Unlike the
Sensitive re-gate (ADR-0016), the gateway does **not** independently re-enforce
the Comfort seat gate against its own ingested CAN state.  A compromised rich
domain could in principle ALLOW a driver-seat adjustment while in motion.
Acceptable for the demo tier; a future ADR may extend gateway re-gating to the
Comfort seat path.

## Consequences

**Positive:**
- Eliminates a driver-distraction hazard: an AI agent cannot autonomously adjust
  the driver's seat position at highway speed.
- Pure, deterministic gate — no new I/O, no clock dependency, no heap allocation.
- Backward-compatible: HVAC, cabin lighting, and media remain unconditionally ALLOW.
- The 30 km/h threshold is well below highway speeds but allows adjustment in
  parking lots and slow traffic.

**Negative / trade-offs:**
- Passenger seat adjustments are always ALLOW regardless of speed; this is correct
  by design but means a passenger agent cannot be restricted.  OEMs who need
  passenger-zone gating must extend `evaluate_comfort_state` with an explicit
  passenger policy.
- Requires vehicle state to be supplied to exercise the gate; if state is absent
  the gate does not fire (Comfort safe by omission).  For Comfort this is
  acceptable — unlike Sensitive tools where the absence of state must be
  fail-dangerous.
- The gate lives in the rich domain (`decide()`) and is not independently
  re-enforced at the gateway (see Known Limitation above).

## References

- `crates/a2g-core/src/vehicle.rs` — `evaluate_comfort_state()`,
  `SPEED_GATE_MMPS`, `is_comfort_seat_tool()`
- `crates/a2g-core/src/enforce.rs` — integration in `decide()`
- ADR-0005 (capability model), ADR-0016 (gateway state feeds `verified_state`)
