# A2G Governance Demo

## What you're watching — and why it matters

Modern vehicles are software-defined machines. An AI agent running inside the
cabin can request hundreds of in-vehicle actions per second — adjusting climate,
moving windows, controlling doors, even modulating throttle. Without a
governance layer, "allow everything" is the only option, and that is not
acceptable in a safety-critical system.

A2G (Agent-to-Gateway) is that governance layer. The demo below runs four
requests through the full enforcement pipeline and shows you the result on a
real CAN bus. **Two of the four requests reach the bus as enforcement frames.
Two do not.** The silence on the bus during the blocked beats is not a bug — it
is the system working exactly as intended.

---

## Prerequisites

| Tool | Notes |
|------|-------|
| Rust + Cargo | `rustup toolchain install stable` |
| Linux kernel ≥ 4.9 | `vcan` module required for real CAN frames |
| `can-utils` (optional) | `candump vcan0` gives a second independent view |

---

## Bring up a virtual CAN interface

> **vcan0 is required for the real visual demo.**  
> The CI fallback runs the same four-beat logic with a simulated bus and is
> useful for automated testing, but it does not produce real CAN frames and
> is **not** the demo path.

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Verify: `ip link show vcan0` should show `UP`.

To tear it down afterwards:

```bash
sudo ip link del vcan0
```

---

## Build

```bash
cargo build --release -p a2g-demo
```

The binary lands at `target/release/a2g-demo`.

---

## Run the demo (two terminal panes)

### Pane 1 — Bus listener

Start this first so you see every frame as it arrives:

```bash
./target/release/a2g-demo listen --iface vcan0
```

The listener prints only frames with CAN ID `0x7A2` (A2G enforcement frames).
Silence in this pane during beats 2 and 3 is intentional and meaningful.

### Pane 2 — Showcase

```bash
./target/release/a2g-demo run --vcan vcan0 --pause
```

`--pause` waits for Enter between beats — useful for screen recording or
live narration. Drop it for an automated run.

---

## What happens in each beat

| Beat | Tool | Core verdict | Gateway | Bus |
|------|------|--------------|---------|-----|
| 1 | `vehicle.climate.set_temperature` | ALLOW | Enforced | **Frame appears** |
| 2 | `vehicle.window.set_position` at 120 kph | DENY (speed gate) | *never called* | **Silent** |
| 3 | `vehicle.powertrain.set_throttle` with fabricated receipt | *skipped* | Refused (forbidden) | **Silent** |
| 4 | `vehicle.door.unlock` (HITL Phase-2 ALLOW) | ALLOW | Enforced | **Frame appears** |

Beat 3 is the most important moment: the agent presents a cryptographically
valid signature over a receipt it created itself — but the gateway's
forbidden-tool re-check fires unconditionally **before** signature verification
and refuses the request. A valid signature is not enough to move a forbidden
action onto the bus.

---

## Automated CI fallback (no vcan0)

The integration test in `crates/a2g-demo/tests/showcase_ci.rs` runs all four
beats with an embedded gateway and a simulated CAN bus. It verifies the
correctness of each beat's outcome but does not write real CAN frames.

```bash
cargo test -p a2g-demo
```

---

## Screen recording tips

1. Set your terminal font to ≥ 16 pt and use a dark theme — the ANSI colors
   (green agent, yellow core, cyan gateway, magenta frames) are easier to read.
2. Side-by-side panes: listener on the left, showcase on the right.
3. Use `--pause` so you can narrate each beat before pressing Enter.
4. Point at the listener pane during beats 2 and 3 to make the silence visible.
5. `candump vcan0` in a third pane gives a low-level corroboration that the
   frame bytes on the bus match what the gateway printed.
