# Fixed-Point Determinism — a2g-core

## Purpose

`decide()` and every function on its call path operate in pure integer arithmetic.
No `f32` or `f64` instruction executes between the ingress boundary and the verdict.
This guarantees **bit-identical results** across any target: hardware FPU, soft-float
library, simulator, or bare-metal no_std environment.

Motivation: automotive safety islands (ASIL-B context) and simulation environments
must produce the same verdicts without depending on the floating-point implementation
of the executing CPU. Integer arithmetic is deterministic by construction.

## Fixed-Point Speed Encoding

Speed is the only physical quantity on the decision path.

| Property | Value |
|---|---|
| Field name | `speed_mmps` |
| Type | `u32` |
| Unit | millimetres per second (mm/s) |
| Valid range | 0–277 778 mm/s (0–1 000 km/h) |
| Gate threshold | `SPEED_GATE_MMPS = 1 389` mm/s |
| Fail-safe | `FAIL_SAFE_SPEED_MMPS = 277 500` mm/s (999 km/h) |

### Why mm/s

- Converts 5.0 km/h to 1388.888... mm/s, which rounds to **1 389** — an exact integer threshold.
- Represents all realistic vehicle speeds (0–300 km/h → 0–83 333 mm/s) in a `u32`.
- Fail-safe value 999 km/h = 277 500 mm/s is exact (no rounding).

### Conversion Formula

```
speed_mmps = round(speed_kph × 1 000 000 ÷ 3 600)
```

Implemented in `a2g_core::vehicle::speed_kph_to_mmps()`. This is the **only** place
a float-to-integer conversion occurs on the vehicle-state path.

## Boundary Rejection Rule

Float inputs arriving from AAOS telemetry or operator JSON are validated at the
ingress boundary **before** constructing `VehicleState`. Invalid values are rejected;
they never reach `decide()`.

| Rejected condition | Error |
|---|---|
| NaN | `"speed is NaN"` |
| ±Infinity | `"speed is infinite"` |
| Negative (`< 0.0`) | `"speed is negative"` |
| Subnormal | `"speed is subnormal"` |
| `> 1 000.0 km/h` | `"speed exceeds SPEED_MAX_KPH"` |

At each ingress site, rejection returns `None`/`NULL`/`Err`, which causes the
caller to fall back to the fail-safe DENY state — consistent with the
panic-freedom contract in `docs/PANIC_FREEDOM.md`.

## Ingress Sites

| Site | Language | Rejection action |
|---|---|---|
| `a2g_core::vehicle::speed_kph_to_mmps()` | Rust | `Err(&'static str)` |
| `a2g_ffi::a2g_verified_state_operator_trusted()` | Rust/C ABI | return `NULL` |
| `a2g_conformance::build_vehicle_state()` | Rust (test harness) | return `None` → fail-safe |
| JSON deserialization via `extract_vehicle_state()` | Rust | fail-safe if field missing/wrong type |

## Grep Verification

To confirm no float appears on the decision path in `a2g-core`:

```sh
grep -rn 'f32\|f64' crates/a2g-core/src/
```

Expected output: only in `speed_kph_to_mmps()` (the boundary converter) and its
doc comment. Zero occurrences in `enforce.rs`, `vehicle::is_parked_and_stopped()`,
or any other function that `decide()` calls.

The `speed_kph_to_mmps` function itself performs float operations to validate and
convert the input, but it returns `u32`; no float value escapes it.

## Bit-Identity Proof

The property test `prop_arbitrary_speed_mmps_never_panics` in
`crates/a2g-core/tests/panic_freedom.rs` constructs `VehicleState` with arbitrary
`u32` speed values (0..=u32::MAX) and asserts `decide()` returns without panic.
Since `u32` arithmetic is defined to be the same on every conforming target, the
verdict is bit-identical on all platforms for the same input integer.

The complementary test `prop_boundary_float_to_mmps_never_panics` feeds any `f64`
value (NaN, ±∞, subnormal, normal) to `speed_kph_to_mmps()` and verifies it never
panics — confirming the boundary is safe for all float inputs.

## Honest Residuals

1. **Conversion precision.** The 5.0 km/h threshold maps to 1388.888... mm/s
   (irrational). The integer threshold 1 389 introduces a ±1 mm/s (≈ 0.0036 km/h)
   imprecision relative to the former float comparison. This affects only speeds
   within 1 mm/s of 5.0 km/h — a range of no practical significance for a gate
   intended to detect a parked vehicle.

2. **Float in `speed_kph_to_mmps` itself.** The conversion function contains float
   multiplication and `round()`. This is intentional: the boundary is where floats
   are consumed and banished. The function is not on the decision path — it runs
   before `VehicleState` is constructed.

3. **Gear and actor fields** are already integer/enum types; no float conversion is
   needed for them.

4. **Other telemetry.** `AttestedVehicleState.attested_at` is a string timestamp;
   freshness is computed with `signed_duration_since()` (integer milliseconds). No
   float on that path either.
