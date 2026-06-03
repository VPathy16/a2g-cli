# ADR-0005: Vehicle Capability Model

**Status:** Accepted  
**Date:** 2026-06-03  
**Branch:** `feat/vehicle-capability-model`

---

## Context

In-cabin automotive agents require a capability taxonomy that reflects the safety stakes of vehicle sub-systems. A mandate-only permission model is insufficient: a compromised or overly permissive mandate must not grant access to safety-critical actuators (powertrain, brakes, steering) under any circumstances, and state-gated actions (opening doors at speed) must be denied even when the mandate explicitly allows them.

Three enforcement layers are needed:

1. **Domain-level hard deny** — forbidden sub-systems rejected before any mandate evaluation.
2. **Vehicle state gating** — sensitive capabilities allowed only when physically safe (parked, stopped).
3. **Mandate escalation** — sensitive capabilities routed to human-in-the-loop by default.

## Decision

### 1. Four-Domain Taxonomy

| Domain | Prefix | Default Decision | State-gated |
|--------|--------|-----------------|-------------|
| Comfort | `vehicle.climate.*`, `vehicle.seat.*`, `vehicle.lighting.*`, `vehicle.media.*` | ALLOW | No |
| Convenience | `vehicle.navigation.*`, `vehicle.phone.*` | ALLOW | Light only |
| Sensitive | `vehicle.door.*`, `vehicle.window.*`, `vehicle.trunk.*`, `vehicle.lock.*` | ESCALATE | Yes — Park + speed < 5 km/h |
| Forbidden | `vehicle.powertrain.*`, `vehicle.chassis.*`, `vehicle.adas.*`, `vehicle.drive.*`, `vehicle.steering.*`, `vehicle.braking.*`, `vehicle.throttle.*` | hard DENY | N/A — denied before any check |

Unknown `vehicle.*` sub-domains are treated as Sensitive (fail-safe).

### 2. Forbidden-Domain Hard Deny

Added as a pre-check in `decide()` — runs **before** Step 0 (revocation) and therefore before any mandate permission check:

```
Pre-check: empty tool name
Pre-check: vehicle forbidden domain → immediate DENY, policy_rule = "vehicle_forbidden_domain: ..."
Step 0: revocation
Step 1: signature
Step 2: TTL
Step 3: tool authorization
Step 4: boundary checks
Step 4.5: vehicle state gating (Sensitive only)
Step 5: jurisdiction
Step 6: escalation
Step 7: rate limit
```

**Invariant:** It is structurally impossible for any mandate permission, escalation grant, or vehicle state to allow a Forbidden-domain tool. The deny is unconditional and emitted before mandate parsing results are used for policy.

### 3. Vehicle State Gating (Step 4.5)

`evaluate_vehicle_state(tool, &state) -> StateVerdict` is a pure function with no I/O, no wall-clock access, and no heap allocation on the Allow path (`StateVerdict::Deny` carries `&'static str`).

**Rule (all Sensitive sub-domains):** `speed_kph < 5.0 AND gear == Park` → Allow; else Deny.

**Fail-safe default:** If the caller omits `vehicle_state` from params, `VehicleState::fail_safe()` is used: `{speed_kph: 999.0, gear: Drive, actor: Driver}`. This ensures omission of state is treated as worst-case — Sensitive tools are **denied by omission**.

State is passed via the `vehicle_state` key in params JSON:
```json
{"speed_kph": 0.0, "gear": "Park", "actor": "Driver"}
```

CLI flag: `--vehicle-state '{"speed_kph":0,"gear":"Park","actor":"Driver"}'` is merged into params before `enforce()` is called.

### 4. New Module: `vehicle.rs`

`crates/a2g-core/src/vehicle.rs` exports:
- `VehicleDomain` — 5-variant enum
- `Gear`, `Actor` — serde-serialisable enums
- `VehicleState` — with `fail_safe()` and `is_parked_and_stopped()` methods
- `StateVerdict` — `Allow` | `Deny(&'static str)`
- `classify_vehicle_tool(tool: &str) -> VehicleDomain`
- `evaluate_vehicle_state(_tool: &str, state: &VehicleState) -> StateVerdict`
- `extract_vehicle_state(params: &serde_json::Value) -> VehicleState`

### 5. no_std Compatibility

`classify_vehicle_tool()` and `evaluate_vehicle_state()` are pure with no heap allocation on the Allow path. `extract_vehicle_state()` uses `serde_json` — already a no_std blocker (see `docs/no_std-blockers.md`, Blocker 7). No new blockers are introduced by the vehicle module.

## Test Matrix for `examples/in-cabin-assistant.mandate.toml`

| Tool | State | Expected |
|------|-------|----------|
| `vehicle.climate.set_temperature` | Any (moving, stopped, any actor) | ALLOW |
| `vehicle.seat.adjust_lumbar` | Any | ALLOW |
| `vehicle.navigation.set_destination` | Any | ALLOW |
| `vehicle.window.set_position` | Park, 0 km/h, Driver | ESCALATE (in mandate escalation list) |
| `vehicle.window.set_position` | Drive, 60 km/h | DENY (`vehicle_state_violation`) |
| `vehicle.door.unlock` | Park, 0 km/h | ESCALATE |
| `vehicle.door.unlock` | Drive, 30 km/h | DENY (`vehicle_state_violation`) |
| `vehicle.door.unlock` | Omitted (fail-safe) | DENY (`vehicle_state_violation`) |
| `vehicle.powertrain.start_engine` | Any (even if in mandate) | DENY (`vehicle_forbidden_domain`) |
| `vehicle.braking.apply_emergency` | Any | DENY (`vehicle_forbidden_domain`) |

## Consequences

### Positive

- Safety-critical domains are unconditionally protected regardless of mandate contents.
- State gating prevents hazardous window/door operations at speed even when permitted by mandate.
- Fail-safe default (deny by omission) prevents accidents when vehicle state is not supplied.
- `evaluate_vehicle_state()` is deterministic and testable without mocking I/O.
- Extends the existing pipeline non-destructively — existing mandates are unaffected.

### Neutral

- `decide()` has two new pre-checks with negligible CPU cost (prefix string comparison).
- `classify_vehicle_tool()` adds one stack-allocated `Vec` per call for unknown sub-domains (none for known prefixes).

### Negative

- Sensitive tools require `vehicle_state` in params or CLI flag; omission silently denies (by design).
- `vehicle.media.*` is classified as Comfort (always ALLOW), which may be surprising to operators who expect media controls to be state-gated. This can be overridden by listing media tools in `[escalation].escalate_tools` in the mandate.

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Forbidden check in the mandate parser (Step 3) | Mandate parser already checked; forbidden check must precede it so even a mandate listing a forbidden tool is denied |
| Separate forbidden-domain ledger | Adds I/O and complexity; static prefix check is simpler and faster |
| Passenger-only state gating for windows | Inconsistent with safety model; driver distraction from window operation at speed is equally hazardous |
| Allow comfort tools without any mandate listing | Breaks the explicit allow-list invariant; consistency is more valuable than UX convenience |
