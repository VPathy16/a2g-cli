# A2G

[![CI](https://github.com/VPathy16/a2g-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/VPathy16/a2g-cli/actions/workflows/ci.yml)

**Deterministic authorization layer between an in-cabin AI agent and the vehicle — decides what the agent may do before the action reaches the vehicle, with zero LLM calls in the decision path and a signed audit trail for every verdict.**

The core is general-purpose: it governs any agent's tool calls against a cryptographically-signed mandate. The primary use case, and the centre of gravity for every design decision, is in-cabin automotive.

---

## The problem

AI agents are entering the cockpit. An in-cabin assistant that can adjust climate, navigate, or unlock doors is genuinely useful — but the same capability surface, misused or misbehaving, can unlock a door at highway speed, issue an ADAS command, or silently override a chassis-safety setting.

The gap is not detection. Guardrails and output filters can flag suspicious output after the fact. The gap is **authorization before execution**: a mechanism that answers "was this agent permitted to take that action, at that moment, given the physical state of the vehicle?" and produces a tamper-evident record that the OEM can present as proof.

A2G fills that gap.

---

## How it works

The core idea is: **decide before, not detect after**.

```
 In-Cabin Agent
      │
      │  tool = "DOOR_LOCK", params = {"lock": false}
      ▼
 ┌─────────────────────────────────────────────────────────┐
 │              A2G   decide()                             │
 │                                                         │
 │  Pre-check  Forbidden domain → hard DENY (no mandate   │
 │             permission, escalation, or state can        │
 │             override this)                              │
 │  Step 0     Revocation                                  │
 │  Step 1     Mandate signature (ed25519)                 │
 │  Step 2     TTL                                         │
 │  Step 3     Tool authorization                          │
 │  Step 4     Boundary checks (path / network / command)  │
 │  Step 4.5   Vehicle state gating (Sensitive domain)     │
 │  Step 5     Jurisdiction / operating hours              │
 │  Step 6     Escalation (human-in-the-loop)              │
 │  Step 7     Rate limit                                  │
 └──────────────┬──────────────┬──────────────────────────┘
                │              │
           ALLOW + receipt   DENY + receipt
           (signed, hash-    (signed, hash-
            chained)          chained)
                │
                ▼
      Enforcing layer → VHAL
```

**Three architectural properties:**

1. **Pure and deterministic.** `decide()` takes an explicit clock value, an explicit ledger reference, and the signed mandate. No LLM calls, no filesystem reads, no OS time. Given the same inputs it produces the same verdict — reproducible and replayable from the ledger.

2. **The forbidden domain is a structural guarantee, not a policy.** Safety-critical VHAL properties (propulsion, ADAS, chassis) are denied unconditionally before any mandate field is consulted. No capability entry, escalation grant, or vehicle state can reach this check — the deny is architecturally prior to mandate evaluation.

3. **Decision and enforcement are separate layers.** `decide()` in `a2g-core` is a pure function with no I/O. The enforcing layer (the CLI today; a standalone gateway on the roadmap) calls `decide()`, writes the receipt, and only then forwards a command to VHAL. The agent never touches VHAL directly.

---

## Vehicle capability model

Every vehicle tool call is classified into one of four domains before any mandate check runs.

| Domain | Tool prefixes / VHAL properties | Default verdict | State-gated |
|--------|----------------------------------|-----------------|-------------|
| **Comfort** | `vehicle.climate.*`, `vehicle.seat.*`, `vehicle.lighting.*`, `vehicle.media.*`; HVAC, seat, lighting VHAL properties | ALLOW | No — permitted at any speed, any actor |
| **Convenience** | `vehicle.navigation.*`, `vehicle.phone.*`; navigation audio VHAL properties | ALLOW | Light only |
| **Sensitive** | `vehicle.door.*`, `vehicle.window.*`, `vehicle.trunk.*`, `vehicle.lock.*`; door, window, charge-port VHAL properties | ESCALATE | **Yes — Park and speed < 5 km/h required** |
| **Forbidden** | `vehicle.powertrain.*`, `vehicle.chassis.*`, `vehicle.adas.*`, `vehicle.drive.*`, `vehicle.steering.*`, `vehicle.braking.*`, `vehicle.throttle.*`; ADAS/propulsion/chassis-safety VHAL writes | hard **DENY** | N/A — denied before any check |

Unknown `vehicle.*` sub-domains are treated as Sensitive (fail-safe).

### State gating

Sensitive capabilities (window, door, trunk, lock) require `speed_kph < 5.0 AND gear == Park`. The verdict is DENY — not ESCALATE — when the vehicle is moving; state denial fires before the escalation step.

Vehicle state is passed via `--vehicle-state '{"speed_kph":0,"gear":"Park","actor":"Driver"}'` or via the `vehicle_state` key in `--params`.

### Fail-safe default

If a Sensitive tool call arrives with no vehicle state, `VehicleState::fail_safe()` is used: 999 km/h in Drive. **Omitting vehicle state for a Sensitive tool is a DENY, not an ALLOW.** Agents must assert the physical state explicitly.

---

## AAOS / VHAL fit

A2G's capability model speaks AAOS `VehicleProperty` symbolic names directly. Mandate authors can write `HVAC_TEMPERATURE_SET`, `DOOR_LOCK`, or `CRUISE_CONTROL_COMMAND` instead of generic `vehicle.*` strings. Both forms classify to the same domain; existing mandates using the `vehicle.*` form continue to work unchanged.

The agent **never calls VHAL directly.** A2G mediates every access: the agent proposes a VHAL property name as the tool, A2G's `decide()` evaluates the mandate, and only on `ALLOW` does the enforcing layer forward the command to the HAL. On `DENY` or `ESCALATE` the command is blocked and a receipt is written.

Read-only telemetry properties (`PERF_VEHICLE_SPEED`, `GEAR_SELECTION`, `ENGINE_RPM`) resolve to the NonVehicle domain — the agent may observe vehicle state, but reading telemetry is not a governed capability and is never subject to the Forbidden or Sensitive checks.

Full property-to-domain mapping: [`docs/aaos-vhal-mapping.md`](docs/aaos-vhal-mapping.md)

---

## Quick start

```bash
# Build
cargo build --release

# Create governance root and in-cabin agent identities
./target/release/a2g sovereign
./target/release/a2g init --name cabin-agent
```

Edit `examples/in-cabin-assistant.mandate.toml` to set `agent_did` to the value in `cabin-agent.did`, then sign it:

```bash
./target/release/a2g sign \
    --mandate examples/in-cabin-assistant.mandate.toml \
    --key sovereign.secret.key --ttl 24 --skip-proposal
```

### Forbidden domain — hard DENY

The forbidden pre-check fires before signature verification and before any mandate field is consulted. No mandate permission can reach a Forbidden property.

```bash
./target/release/a2g enforce \
    --mandate examples/in-cabin-assistant.mandate.toml \
    --tool CRUISE_CONTROL_COMMAND \
    --params '{}'
```

```
DENY ✗
  tool:    CRUISE_CONTROL_COMMAND
  reason:  vehicle_forbidden_domain: 'CRUISE_CONTROL_COMMAND' is in the
           safety-critical domain and cannot be granted by any mandate
  receipt: <uuid>
```

### Comfort domain — ALLOW at any speed

```bash
./target/release/a2g enforce \
    --mandate examples/in-cabin-assistant.mandate.toml \
    --tool HVAC_TEMPERATURE_SET \
    --params '{"zone":"driver","target_temp_c":22}'
```

```
ALLOW ✓
  tool:    HVAC_TEMPERATURE_SET
  rule:    all_checks_passed
  receipt: <uuid>
```

### Sensitive domain — state-gated

```bash
# Parked and stopped — escalates to human-in-the-loop (mandate escalation list)
./target/release/a2g enforce \
    --mandate examples/in-cabin-assistant.mandate.toml \
    --tool DOOR_LOCK \
    --params '{"door_index":0,"lock":false}' \
    --vehicle-state '{"speed_kph":0,"gear":"Park","actor":"Driver"}'
```

```
ESCALATE ⬆
  tool:    DOOR_LOCK
  reason:  escalation_required: tool 'DOOR_LOCK' requires approval from ...
  receipt: <uuid>
```

```bash
# Moving — state gate fires before escalation
./target/release/a2g enforce \
    --mandate examples/in-cabin-assistant.mandate.toml \
    --tool DOOR_LOCK \
    --params '{"door_index":0,"lock":false}' \
    --vehicle-state '{"speed_kph":60,"gear":"Drive","actor":"Driver"}'
```

```
DENY ✗
  tool:    DOOR_LOCK
  reason:  vehicle_state_violation: sensitive capabilities (window/door/trunk/lock)
           require speed_kph < 5.0 and gear == Park
  receipt: <uuid>
```

### Audit trail

Every enforce call writes a signed, hash-chained receipt. Query the ledger:

```bash
./target/release/a2g audit --ledger a2g_ledger.db --last 10
./target/release/a2g audit --ledger a2g_ledger.db --decision DENY
```

---

## Status and maturity

| Works today | Roadmap |
|---|---|
| Deterministic governance engine (`decide()`) | Standalone enforcing gateway (separate runtime process; today `decide()` is advisory — the mediator is specified, not yet a compiled component) |
| Four-domain vehicle capability model (Comfort / Convenience / Sensitive / Forbidden) | Embeddable Rust crate with C-ABI for OEM integration |
| AAOS `VehicleProperty` symbolic-name support (ADR-0006) | Live vehicle-signal ingestion for automatic `VehicleState` population |
| Fail-safe state gating (omitted state → Sensitive DENY) | Hardware target / bare-metal no_std build (blockers documented in `docs/no_std-blockers.md`) |
| Signed, hash-chained SQLite ledger with execution lineage | ISO 26262 / ISO 21434 alignment (not a current feature; not claimed) |
| Pure `a2g-core` crate: no SQLite, no_std-scaffolded, embeddable | |
| ed25519 mandate signing, revocation, delegation chains | |
| 73 unit tests, 37 adversarial battle tests | |

**Enforcement is advisory today.** The `decide()` pipeline is deterministic and production-quality, but there is not yet a separate enforcing component that sits as a runtime gateway between the agent process and the VHAL HAL. That component is the next significant milestone.

---

## Architecture and decision record

The ADR trail documents every significant design decision and the tradeoffs considered:

| ADR | Decision |
|---|---|
| [ADR-0001](docs/adr/0001-core-cli-split.md) | `a2g-core` / `a2g-cli` workspace split — pure core, SQLite in CLI only |
| [ADR-0004](docs/adr/0004-pure-decision-path.md) | Pure `decide()` with injected clock; `enforce()` as the std-layer wrapper |
| [ADR-0005](docs/adr/0005-vehicle-capability-model.md) | Four-domain vehicle capability model — forbidden hard-deny, state gating, fail-safe default |
| [ADR-0006](docs/adr/0006-aaos-vhal-mapping.md) | AAOS VHAL naming layer — A2G as mediator, backward compatibility, no new no_std blockers |

VHAL property mapping table: [`docs/aaos-vhal-mapping.md`](docs/aaos-vhal-mapping.md)

no_std scaffold and blockers: [`docs/no_std-blockers.md`](docs/no_std-blockers.md)
