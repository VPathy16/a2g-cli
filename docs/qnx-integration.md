# QNX 8.0 Integration Guide

This document describes how to build a2g-gateway and a2g-core for QNX 8.0
(Neutrino RTOS), what is stubbed vs. fully implemented, and how to attach the
gateway to a real CAN network or hypervisor channel.

See ADR-0019 for the design decisions behind the platform seam.

---

## Target triple

**`aarch64-unknown-nto-qnx800`** — AArch64, QNX 8.0 Neutrino.

This is the documented Rust target triple for QNX SDP 8.0 on AArch64. It is a
**Tier 3** Rust target (nightly only as of 2026) and is not available in the
stable rustup channel without a QNX SDP installation.

For `x86_64` development VMs: `x86_64-pc-nto-qnx800` is the analogous triple.

---

## Toolchain setup

### Option A — QNX SDP 8.0 (full build)

1. Install QNX SDP 8.0 from [blackberry.qnx.com](https://blackberry.qnx.com).
   A commercial licence is required.

2. Source the QNX environment:

   ```bash
   source /path/to/qnx800/qnxsdp-env.sh
   ```

3. Install Rust nightly and the QNX target:

   ```bash
   rustup toolchain install nightly
   rustup target add aarch64-unknown-nto-qnx800 --toolchain nightly
   ```

4. Configure the linker in `.cargo/config.toml`:

   ```toml
   [target.aarch64-unknown-nto-qnx800]
   linker = "aarch64-unknown-nto-qnx800-gcc"
   ```

5. Build:

   ```bash
   cargo +nightly build -p a2g-gateway --target aarch64-unknown-nto-qnx800
   cargo +nightly build -p a2g-core --target aarch64-unknown-nto-qnx800
   ```

### Option B — cargo check only (no SDP, CI)

`cargo check` does not invoke the linker and succeeds without the QNX SDP if
the target's `core` library is available:

```bash
rustup toolchain install nightly
# The target may fail to install on rustup stable; use nightly:
rustup target add aarch64-unknown-nto-qnx800 --toolchain nightly
cargo +nightly check -p a2g-gateway --target aarch64-unknown-nto-qnx800
cargo +nightly check -p a2g-core --target aarch64-unknown-nto-qnx800
```

**Limitation:** If the Tier 3 target is not available in the current nightly
(no pre-built `std` component), the check will fail at the `std` compilation
stage. This is a rustup/nightly toolchain limitation, not a code issue. See the
CI job `qnx-check` in `.github/workflows/ci.yml` for the exact invocation used
in automated CI.

---

## What compiles

| Module | Status | Notes |
|--------|--------|-------|
| `a2g-core` (all) | Full compile | Pure Rust, no OS I/O |
| `a2g-gateway::transport` | Full compile | `Read` + `Write` traits, no OS calls |
| `a2g-gateway::bus` — simulated path | Full compile | Falls back to simulated bus on NTO |
| `a2g-gateway::bus` — SocketCAN path | Linux only | `#[cfg(target_os = "linux")]` |
| `a2g-gateway::state_ingest` — frame logic | Full compile | CRC, encoding, verification: pure |
| `a2g-gateway::state_ingest` — reader thread | Stub on NTO | See §CAN Driver Integration |
| `a2g-gateway::server` — Unix socket listener | Full compile | QNX is `cfg(unix)` |
| `a2g-gateway::keys`, `pending`, `protocol` | Full compile | |
| `a2g-gateway` binary | Full compile | Signal handling via `libc` POSIX |

---

## What is stubbed and why

### SocketCAN reader (`state_ingest::reader_loop`)

SocketCAN (`AF_CAN`, `SIOCGIFINDEX`, `sockaddr_can`) is a Linux kernel
subsystem with no equivalent in QNX. The QNX platform seam in
`state_ingest.rs` provides a `#[cfg(target_os = "nto")]` stub that:

1. Logs `"QNX CAN driver: real dev-can-* integration required for <iface>; state stays fail-safe (fail-closed)"`.
2. Returns immediately without reading any frames.

**Consequence (fail-closed):** When the gateway is started with
`--state-ingest`, `reader_active` is set to `true` (in `spawn_reader`, before
the thread runs), but no frames are ever ingested. Every call to
`current_state()` returns `fresh = false`. The `handle_enforce` path then
refuses all Sensitive tools with `"state_authority_mismatch: --state-ingest
reader is active but CAN frames are stale"`. This is the **correct fail-closed
behaviour** — the gateway never assumes the vehicle is parked.

To deploy on real QNX hardware, implement the `reader_loop` body (see §CAN
Driver Integration below).

### SocketCAN write path (`bus::write_enforcement_frame`)

On QNX, `try_write_real()` returns `false` (the `#[cfg(not(target_os = "linux"))]`
branch). The gateway writes the enforcement frame to stdout with the
`SIMULATED_FRAME_PREFIX` marker. This is the same fallback as Linux CI (no
`vcan0` loaded). It is safe: verdict logging still occurs; only the physical
CAN write is absent.

---

## CAN Driver Integration (real hardware)

QNX 8.0 supports CAN via character-device drivers in the `dev-can-*` family:

- `dev-can-mx6x` — NXP i.MX6/8 FlexCAN
- `dev-can-kvaser` — Kvaser USB adapters
- `dev-can-audi` / OEM-specific drivers

Two integration paths exist:

### Path A — QNX CAN Socket library (`-lcanctl`)

QNX SDP 8 includes an optional CAN Socket library that provides a
BSD-socket-like interface (`socket(AF_CAN, SOCK_RAW, CAN_RAW)`). If your BSP
includes this library:

1. Start the `dev-can-*` driver in your image build (`bsp.build` / `build`
   script).
2. In `reader_loop` (the `#[cfg(target_os = "nto")]` block in
   `state_ingest.rs`), replace the stub with:

   ```rust
   // Requires: link against -lcanctl in build.rs or Cargo.toml [target.'cfg(target_os = "nto")'.build-dependencies]
   unsafe {
       let fd = libc::socket(AF_CAN, libc::SOCK_RAW, CAN_RAW);
       // bind to the interface by ifindex (same pattern as the Linux path in bus.rs)
       // … read loop identical to the Linux reader_loop above …
   }
   ```

3. Add `#[link(name = "canctl")]` or `println!("cargo:rustc-link-lib=canctl")`
   in a `build.rs` for `a2g-gateway`.

### Path B — devctl() / QNX-native API

If the CAN Socket library is not available, use the `devctl()`-based API
provided by the `dev-can-*` driver directly. This requires the QNX DDK headers
and is driver-specific. Consult the BSP documentation for your hardware.

---

## Unix socket transport

The gateway uses `std::os::unix::net::{UnixListener, UnixStream}` for its IPC
socket. QNX Neutrino fully supports `AF_UNIX` (POSIX.1), so the Unix socket
transport compiles and runs on QNX without modification.

The default socket path is `/tmp/a2g-gateway.sock`. On QNX, `/tmp` is
typically a RAM filesystem (tmpfs). This is acceptable for the demo tier.

---

## Hypervisor attachment (guest ↔ host)

If the gateway runs inside a **QNX hypervisor guest partition** (e.g., as a
safety-island process in a mixed-criticality system with a Linux rich-domain
guest), Unix domain sockets do not cross the hypervisor boundary. Options:

### Shared memory + QNX pulse channels

Use a shared-memory ring buffer with QNX pulse notifications for the
`GatewayRequest` / `GatewayResponse` CBOR frames. The wire encoding
(`transport::write_frame` / `transport::read_frame`) is reusable — only the
underlying `Read`/`Write` implementor changes.

### vsock (hypervisor virtual socket)

If the hypervisor provides a vsock device (`/dev/vsock` or equivalent), a
standard `std::net::TcpStream` to `VMADDR_CID_HOST` can carry the same
length-prefixed CBOR frames. The transport module is already wire-format
agnostic — the `write_frame`/`read_frame` helpers accept any `Read + Write`.

To enable TCP fallback for hypervisor testing:

```bash
a2g-gateway --socket tcp://127.0.0.1:9274
```

> **Not yet implemented.** The TCP listener option is documented as a future
> extension. The current implementation only supports Unix domain sockets.
> An `#[cfg(feature = "tcp-transport")]` feature flag is reserved for this.

---

## Honest assessment of untested items

The following items have **not** been validated on real QNX hardware and may
require further work:

| Item | Status | Risk |
|------|--------|------|
| `cargo check` for `aarch64-unknown-nto-qnx800` | Attempted in CI; target availability depends on nightly | Medium — Tier 3 target may not always be installable |
| `cargo build` (full link) | Not tested — requires QNX SDP licence | High — linker symbol mismatches possible |
| `getrandom`/`rand` entropy on NTO | Documented as supported via `/dev/urandom`; untested | Low |
| `chrono` wall clock on NTO | Uses `libc::clock_gettime(CLOCK_REALTIME)`; POSIX | Low |
| CAN driver integration | Stub only | N/A for CI; requires hardware |
| Signal handling (`SIGINT`/`SIGTERM`) | POSIX; expected to work | Low |
| Unix socket permissions on QNX | Expected standard POSIX behaviour | Low |

---

## Running the test plan on Linux (required before QNX deployment)

All five standard commands must pass on Linux before a QNX deployment:

```bash
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check --all
cargo run -p a2g-conformance
cargo test -p a2g-gateway --test adversarial
```

These commands are run in CI on every PR and must remain green.
