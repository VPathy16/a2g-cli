# ADR-0016: Gateway-Side Vehicle State Ingestion

**Status:** Accepted  
**Date:** 2026-06-11  
**Supersedes:** —  
**Superseded by:** —  
**Related:** ADR-0007 (attested vehicle state), ADR-0010 (enforcing gateway)

---

## Context

Prior to this ADR the gateway's enforcement path accepted the vehicle state on
faith from the rich domain. A `VerifiedVehicleState` with `StateTrust::OperatorTrusted`
was produced from caller-supplied JSON; the gateway verified the receipt signature
and freshness but never independently confirmed the physical vehicle state.

This left a gap: a compromised rich domain could construct a validly-signed ALLOW
receipt for a Sensitive capability (door, window, trunk, lock) while the vehicle
was actually moving, and the gateway would enforce it.

## Decision

The Enforcing Gateway subscribes directly to SocketCAN and applies AUTOSAR-E2E
E2E-inspired integrity protection (CRC-8/SAE-J1850 + alive counter) to every
ingested frame. Sensitive-domain enforcement is **re-gated** against the gateway's
own ingested state; a receipt from the rich domain cannot override the gateway's
independent reading.

### Wire format (demo profile)

Both frames are 8 bytes with a shared E2E trailer:

| Signal | Default CAN ID | Content bytes 0–5 | Byte 6 | Byte 7 |
|--------|----------------|-------------------|--------|--------|
| Speed  | `0x3A0`        | `speed_mmps` u32 LE (0–3), reserved (4–5) | alive counter (low nibble, 0–14) | CRC-8/J1850 over bytes 0–6 ∥ `SPEED_DATA_ID=0xA0` |
| Gear   | `0x3A1`        | gear byte (0=P,1=R,2=N,3=D), reserved (1–5) | alive counter (low nibble, 0–14) | CRC-8/J1850 over bytes 0–6 ∥ `GEAR_DATA_ID=0xA1` |

The data ID in the CRC input provides masquerade protection: a gear frame
replayed on the speed CAN ID fails the CRC.

### Verification rules

A frame is **rejected** (counted, not ignored silently) when:

1. **CRC mismatch** — `crc8_j1850(bytes[0..7] ∥ data_id) ≠ bytes[7]`
2. **Repeated alive counter** — same counter value as the previous accepted frame
   (frozen sender or replay)
3. **Invalid counter nibble** — value `15` (E2E reserved invalid)
4. **Invalid gear value** — byte 0 outside 0–3

### Fail-safe degradation

If either signal has not been refreshed by a valid frame within
`ATTESTATION_FRESHNESS_MS` (500 ms), `StateIngest::current_state()` returns the
fail-safe: `speed_mmps = FAIL_SAFE_SPEED_MMPS (277 500 mm/s)`, gear `Drive`,
`fresh = false`. Moving without data is the safe assumption (SPEC §6.6).

### Gateway re-gating

In `handle_enforce()`, after all existing 7 steps:

- If the tool is in the **Sensitive** domain and the gateway has **fresh** ingested
  state:
  - If `is_parked_and_stopped()` is false → `REFUSE state_authority_mismatch`
  - If `is_parked_and_stopped()` is true → pass (gateway confirms the rich domain)
- If the gateway has **no fresh** state **and the reader is active** (`--state-ingest`
  was passed at startup):
  - **`REFUSE state_authority_mismatch`** (fail-closed). A bus timeout does not reopen
    GAP-1 — once the operator has opted into bus-verified re-gating, stale data is not
    a legitimate fallback to unverified state. A CAN bus outage must surface as
    enforcement failures, not silent degradation.
- If the gateway has **no fresh** state **and the reader was never started** (no
  `--state-ingest`):
  - If `state_trust == "operator_trusted"` → log a warning; enforcement proceeds
    (backward-compatible for deployments without `--state-ingest`)
  - If `state_trust == "attested"` → already independently verified above (step 8
    in `server.rs`); no additional warning needed

### Startup flag

`a2g-gateway --state-ingest` spawns the background reader on the `--vcan`
interface. Without this flag the `StateIngest` struct is present but never fed
frames, so it stays fail-safe and only emits the warning path.

### State simulator

`a2g-state-sim --vcan <iface> --speed-kph <f64> --gear <park|reverse|neutral|drive>`
broadcasts valid E2E-protected frames at 50 Hz. Integration tests use a
`vcan0` loopback to feed the gateway and verify the re-gating path.

## Consequences

**Positive:**
- The gateway is no longer solely dependent on the rich domain's state claim for
  Sensitive enforcement. A compromised or buggy rich domain cannot synthesize
  a moving state as parked.
- The `operator-state` Cargo feature (ADR-0016 side effect) demotes
  `from_operator_trusted()` to a compile-time opt-in, so production builds of
  `a2g-core` can make unattested state a compile error.

**Negative / trade-offs:**
- `--state-ingest` is optional. Deployments that omit it revert to the pre-ADR-0016
  behavior for Sensitive tools with `operator_trusted` receipts.
- The demo wire format (two fixed CAN IDs, u32 LE speed) is not the AAOS VHAL
  wire format; a production deployment must translate from the OEM's actual CAN
  signals. The CAN ID constants and encode/verify functions are intentionally
  public so an integrator can swap the demo frame layout.
- CRC-8/SAE-J1850 provides basic data integrity, not authenticated authorization.
  A physical adversary with bus access can still inject frames. The gateway
  mitigates replay (alive counter) and masquerade (data ID in CRC), but not a
  live active attack. Full bus security requires CAN-SEC or SecOC, which is
  out-of-scope for the demo tier.

## References

- AUTOSAR E2E Protocol Specification (AUTOSAR_SWS_E2ELibrary) — Profile 1
  (CRC-8/SAE-J1850, poly 0x1D). **Not** Profile 2 (CRC-8H2F, poly 0x2F).
- SAE J1850 — Class B Data Communication Network Interface
- `crates/a2g-gateway/src/state_ingest.rs` — implementation
- `crates/a2g-gateway/src/bus.rs` — `CanReader` (also writes enforcement frames)
- SPEC §6.6 (fail-safe speed), §6.8 (speed encoding), §10.1 (production mode)
