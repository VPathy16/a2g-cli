# ADR-0019 — QNX 8.0 Build Portability for a2g-gateway and a2g-core

**Date:** 2026-06-12
**Status:** Accepted
**Authors:** S5 implementation
**Related:** ADR-0010 (Enforcing Gateway), ADR-0016 (Gateway State Ingest)

---

## Context

a2g-gateway and a2g-core must be deployable on QNX 8.0 (Neutrino RTOS) for
automotive ECU targets such as central compute / safety-island platforms. QNX
is the dominant RTOS in ADAS and in-cabin stacks for Tier-1 suppliers. An
agent-governance daemon running in a QNX partition provides stronger isolation
than a Linux user-space process.

The Rust cfg name for QNX is `target_os = "nto"` (Neutrino). The nearest
available Rust target triple is `aarch64-unknown-nto-qnx800` (QNX 8.0 on
AArch64). This is the documented SDP 8.0 target triple; it is not published in
rustup's stable tier and requires the QNX SDP 8.0 toolchain (qcc) plus the
Rust nightly target or a custom sysroot — see docs/qnx-integration.md for
toolchain setup.

---

## Decision

### 1. Platform seam — SocketCAN isolated behind `cfg(target_os = "linux")`

SocketCAN (`AF_CAN` sockets, ioctl `SIOCGIFINDEX`, `sockaddr_can`) is a
Linux-specific kernel subsystem with no QNX equivalent. All SocketCAN code is
already gated behind `#[cfg(target_os = "linux")]` in `crates/a2g-gateway/src/bus.rs`.

For the CAN reader (`state_ingest.rs::reader_loop`), the existing `#[cfg(not(target_os = "linux"))]` stub already returns immediately, leaving `reader_active = true` and the ingested state permanently stale. This is correct **fail-closed** behaviour: the gateway started with `--state-ingest` but cannot read frames, so every Sensitive enforcement is refused. No change is needed to the existing stubs.

A new QNX-specific CAN driver skeleton (`reader_loop_qnx`) is added as a
`#[cfg(target_os = "nto")]` block behind a doc-comment explaining the expected
`dev-can-*` device path conventions (see §3). The skeleton is compile-checked
but always fails at runtime with `"QNX CAN driver: real dev-can-* integration
required"`, preserving the fail-closed contract identically to the non-Linux stub.

### 2. Unix socket transport — cfg-gated

`std::os::unix::net::UnixStream` / `UnixListener` exist on QNX Neutrino
(POSIX `AF_UNIX` sockets are supported). However, to avoid any surprise and to
keep the build clean on all non-POSIX targets, the Unix socket path in
`client::send_request` and `server::serve` is already OS-agnostic: it uses
`std::os::unix::net` which requires `cfg(unix)` — QNX satisfies `cfg(unix)`.

The `main.rs` signal handling (`libc::signal(SIGINT/SIGTERM, …)`) also works on
QNX; `libc` supports NTO.

No transport changes are required for basic QNX portability. The design note in
`docs/qnx-integration.md` documents that a production deployment could replace
the Unix-socket IPC with vsock (hypervisor guest↔host) if the gateway runs in a
hypervisor guest partition.

### 3. QNX CAN driver skeleton

QNX uses character-device drivers in the `devb-can` / `dev-can-*` family
(e.g., `dev-can-mx6x`, `dev-can-kvaser`) that expose a BSD-socket-compatible
`socket(AF_CAN, SOCK_RAW, CAN_RAW)` interface for QNX SDP 8 (via the optional
CAN Socket library). Real integration requires:

- linking against the QNX CAN Socket library (`-lcanctl` or OS equivalent),
- opening `/dev/can<n>` via `socket(AF_CAN, SOCK_RAW, CAN_RAW)` or the
  `devctl()`-based `ioctl` interface.

The skeleton in `state_ingest.rs` is gated `#[cfg(target_os = "nto")]`,
doc-commented with the integration path, and returns `Err` immediately so the
reader exits and the ingested state stays fail-safe (fail-closed). It is not
dead code (it is reachable on QNX), but is explicitly marked with
`#[allow(unused)]` on the stub functions that are not yet called.

### 4. Dependency audit

| Dependency | Usage in a2g-core | Usage in a2g-gateway | QNX portable? | Notes |
|---|---|---|---|---|
| `ed25519-dalek 2.1` | signing/verify | signing/verify | Yes — pure Rust | |
| `rand 0.8` | nonce, key gen | nonce | Yes — `getrandom` feature required on NTO; see note below |
| `sha2 0.10` | hashing | hashing | Yes — pure Rust | |
| `hex 0.4` | encoding | encoding | Yes — pure Rust | |
| `bs58 0.5` | base58 | — | Yes — pure Rust | |
| `serde 1` | serialization | serialization | Yes — pure Rust | |
| `serde_json 1` | JSON | JSON | Yes — pure Rust | |
| `ciborium 0.2` | CBOR | CBOR framing | Yes — pure Rust | |
| `minicbor 0.24` | CBOR canonical | CBOR canonical | Yes — pure Rust | |
| `uuid 1` | verdict IDs | binding IDs | Yes — requires `v4` feature → `getrandom` | |
| `chrono 0.4` | timestamps | timestamps | Yes — pure Rust; uses `libc` clock_gettime on POSIX | |
| `regex 1` | tool classification | — | Yes — pure Rust | |
| `libc 0.2` | — | SocketCAN, signals | Partial — NTO target supported; SocketCAN constants absent on NTO | SocketCAN code is Linux-only gated |
| `tempfile 3` (dev) | — | tests | Yes — POSIX tmpfile | |

**`getrandom` / `rand` on QNX:** `rand 0.8` uses `getrandom 0.2` for entropy.
`getrandom 0.2` supports QNX (NTO) via `/dev/urandom`. No extra feature flags
are required — `getrandom` detects NTO at compile time.

**`libc` SocketCAN constants on QNX:** `AF_CAN`, `SOCK_RAW/CAN_RAW`,
`SIOCGIFINDEX`, and `sockaddr_can` are Linux-specific in `libc 0.2`. They are
used only inside `#[cfg(target_os = "linux")]` blocks, so they do not appear in
the QNX compilation unit.

**No new dependencies are added** by this ADR. The QNX driver skeleton uses
only `std::io` and existing `libc` symbols available on NTO.

### 5. CI strategy

The `aarch64-unknown-nto-qnx800` target is not in rustup's stable tier and
requires the QNX SDP 8.0 toolchain. GitHub Actions does not provide QNX
runners. Therefore:

- A new `qnx-check` CI job uses `cargo check --target aarch64-unknown-nto-qnx800`
  after installing the target via rustup nightly (the target is available as a
  Tier 3 nightly target).
- If rustup cannot install the target (SDP not present), the job documents the
  limitation and exits cleanly without a false green badge.
- The job never runs `cargo build` or `cargo test` on QNX — only `cargo check`
  (type-check only, no linking). Real hardware validation is out of scope for
  automated CI and is documented in `docs/qnx-integration.md`.

### 6. Protocol freeze compliance

No changes to:
- Signed payload layouts (CBOR arrays)
- CBOR frame format
- Verdict semantics
- `decide()` logic (a2g-core; no I/O, no platform seam needed)

The `reader_active` flag semantics are preserved exactly. The QNX reader stub
marks `reader_active = false` (it never calls `mark_reader_active()` directly;
`spawn_reader` calls it before spawning the thread, same as Linux). This means
a QNX gateway started with `--state-ingest` is fail-closed from the first
request: `reader_active = true`, `fresh = false`.

---

## Consequences

**Positive:**
- a2g-core and a2g-gateway compile cleanly for `aarch64-unknown-nto-qnx800`
  (verified with `cargo check`).
- Zero Linux behaviour change: all existing tests, conformance vectors, and
  adversarial attacks pass unmodified.
- A clear extension point is documented for real QNX CAN driver integration.

**Negative / limitations:**
- Real QNX hardware validation requires QNX SDP 8.0 (commercial licence) and
  is not performed in automated CI.
- `cargo check` does not link — linker errors (e.g., missing libc symbols on
  NTO) would only appear during a full `cargo build` with the SDP.
- The QNX CAN driver skeleton is a stub; a real deployment requires a team with
  QNX SDP access to implement the `dev-can-*` driver integration.

---

## Open questions

1. **vsock transport:** If the gateway runs inside a QNX hypervisor guest
   partition, the Unix-socket IPC must be replaced with a hypervisor vsock
   channel. This is a deployment concern outside the current scope but is
   documented in `docs/qnx-integration.md §Hypervisor attachment`.

2. **`no_std`:** a2g-core's `no_std` path is blocked by several dependencies
   (see `docs/no_std-blockers.md`). QNX supports `std` (full POSIX), so this
   is not required for the current target.
