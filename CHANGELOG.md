# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — 2026-06-11

### Protocol Freeze

v0.2.0 freezes the following protocol elements. Breaking changes to these
surfaces will require a v0.3.0 (semver minor + changelog entry):

- **CBOR transport frame**: `[u32 BE length][ciborium CBOR body]`.
  `GatewayRequest` and `GatewayResponse` serialized via `serde` + `ciborium`.
- **Receipt canonical payload** (CBOR array `["RECEIPT", …]`): field order,
  types, and tag are normative.  Any change to the signing surface is a
  breaking protocol change.
- **BindingPayload** CBOR array `["BINDING", binding_id, request_hash, escalate_to, ttl_unix_secs]`:
  normative for gateway signing and rich-domain verification.
- **E2E frame layout** (ADR-0016): Speed CAN ID `0x3A0`, Gear CAN ID `0x3A1`,
  `SPEED_DATA_ID=0xA0`, `GEAR_DATA_ID=0xA1`, alive counter modulus 15,
  CRC-8/SAE-J1850 trailer.
- **FFI ABI** (`a2g.h`): `a2g_decide`, `a2g_decide_with_approval`,
  `a2g_trust_anchor_*` signature freeze.

## [Unreleased]

### Added (S5 — QNX 8.0 Build Portability)

- **QNX 8.0 portability for a2g-gateway and a2g-core (ADR-0019)** —
  Both crates compile cleanly for `aarch64-unknown-nto-qnx800` with zero Linux
  regression:
  - SocketCAN isolated behind `#[cfg(target_os = "linux")]` (already the case
    in `bus.rs`; state_ingest.rs stub refined).
  - QNX-specific CAN driver skeleton added (`#[cfg(target_os = "nto")]`
    `reader_loop` stub) with full doc-comments on the `dev-can-*` integration
    path. Fails at runtime with an explicit error, preserving fail-closed
    `reader_active` semantics.
  - Fallback `reader_loop` for any remaining non-Linux/non-NTO targets kept as
    the third arm.
  - Unix socket transport: `std::os::unix::net` is available on QNX (`cfg(unix)`
    is true); no cfg-gating required.
  - `docs/qnx-integration.md`: toolchain setup, compile status table, what is
    stubbed and why, CAN driver integration paths, hypervisor vsock attachment
    notes, honest untested-items table.
  - CI: `qnx-check` job added to `.github/workflows/ci.yml` using
    `cargo +nightly check` for `aarch64-unknown-nto-qnx800`. Job uses
    `continue-on-error: true` to handle Tier 3 target unavailability without
    blocking Linux CI; never fakes a green badge.
  - Protocol freeze: no signed payload changes, no verdict semantic changes,
    no new a2g-core dependencies.

### Added (S2 — MCP Proxy)

- **New crate `a2g-mcp-proxy` (ADR-0020)** — A Model Context Protocol governance
  proxy that wraps any downstream MCP tool server and forces every `tools/call`
  through A2G governance before forwarding:
  - Config (TOML, authoring-side only): downstream command/args, mandate path,
    gateway socket, TrustAnchor source, and a `[tool_map]` table.
  - Default rule: any unmapped tool → `unmapped.<tool_name>` (not in any mandate
    → DENY, fail-closed; audit trail records the real tool name, not a payment namespace).
  - Flow: `map tool → capability` → `decide()` → sign receipt → gateway
    `Enforce` → forward downstream only on gateway accept.
  - DENY/EXPIRED → MCP error `-32001` (`a2g_denied`). Downstream never called.
  - PENDING_APPROVAL (ESCALATE) → MCP error `-32002` (`a2g_escalate`) with
    `binding_id`. Gateway queues the binding via `SignBinding`. Downstream not called.
  - Gateway refuse → MCP error `-32003`. Downstream not called.
  - `DownstreamTransport` trait seam for HTTP/SSE (currently `unimplemented!()`).
  - Stdio MCP JSON-RPC 2.0 with Content-Length framing.
  - `a2g-echo-mcp-server` demo binary: logs every call to stderr for e2e test
    verification.
  - Demo config at `crates/a2g-mcp-proxy/demo/proxy.toml`.
  - README with 10-minute quickstart.
  - 5 e2e tests: (a) allowed call with receipt metadata, (b) denied call with
    zero downstream calls, (c) unmapped tool not forwarded (DENY), (d) `pay.*`
    escalated without binding, (e) missing demo key file rejected at startup.
- **Conformance vector po-010** — ALLOW companion to po-007: `now_ms` pins
  2026-01-15T12:00:00Z (noon UTC, inside 09:00–17:00 window); expected ALLOW.
  Both operating-hours branches (DENY outside / ALLOW inside) are now deterministic.

### Added (S1 — Cockpit Domains)

- **Cockpit domain extension — comms.\*, pay.\*, pii.\* (ADR-0018 / SPEC §3.6)** —
  Three new capability namespaces for in-cabin agents operating beyond vehicle
  control:
  - `pay.*` — All payment-namespace tools require human-in-the-loop approval
    unconditionally (always-HITL). An ALLOW receipt for any `pay.*` tool
    without a Phase 2 binding is refused by the gateway.
  - `comms.call.place`, `comms.sms.send` — Always-HITL. Call placement and
    outbound message sending require explicit human approval on every invocation.
  - `comms.contacts.read`, `comms.history.read` — Require the `"pii.grant"`
    capability sentinel in the mandate's `tools` list; DENY without it.
  - `pii.profile.export` — **Structurally Forbidden** (same tier as
    `CRUISE_CONTROL_COMMAND`). Refused unconditionally before any mandate
    evaluation; no approval grant can override this.
  - `pii.<ns>.read` — Requires `"pii.grant"` sentinel; DENY without it.
  - Unknown `comms.*`, `pay.*`, `pii.*` sub-operations — Always-HITL
    (fail-closed forward-compatibility rule).

- **`pii.grant` capability sentinel** — A new capability token that mandate
  issuers include in `capabilities.tools` to grant PII access. This is
  protocol-freeze-compliant: no new fields are added to `MandateTbs`.

- **`a2g_core::cockpit` module** — `CockpitDomain` enum and
  `classify_cockpit_tool()` pure function; 12 unit tests. Adds three new
  enforcement checks to `decide_core()`:
  - Pre-check: cockpit forbidden domain (after vehicle forbidden).
  - Step 3.5: PII grant sentinel check.
  - Step 6a: Always-HITL cockpit domains (fires before `escalate_tools` check).

- **Gateway cockpit enforcement (ADR-0018)** — `forbidden.rs` extended with
  `is_cockpit_forbidden()` and `requires_hitl_binding()`; `handle_enforce()`
  gains Step 1.5 (cockpit forbidden re-check) and Step 3.5 (always-HITL
  binding guard).

- **Conformance vectors (10-cockpit-domains, 15 vectors)** — cd-001 through
  cd-015 cover pay.* always-HITL, comms.* always-HITL, pii.grant-gated reads,
  pii.profile.export forbidden, unknown cockpit namespace fail-closed, and
  pii.grant sentinel isolation.

- **Adversarial attacks 12–14** — Attack 12: pay.* ALLOW without HITL binding
  (Step 3.5). Attack 13: pii.profile.export cockpit forbidden bypass (Step 1.5).
  Attack 14: pii-gated comms.contacts.read forged with wrong signing key
  (Step 2). All 14 adversarial attacks pass.

### Added

- **CBOR transport framing (P4)** — the Unix socket protocol is now
  length-prefixed CBOR (`[u32 BE len][ciborium body]`), replacing
  newline-delimited JSON.  All `GatewayRequest` / `GatewayResponse` variants
  are serialized with `serde` + `ciborium`. The `transport` module provides
  `write_frame` / `read_frame` helpers and a `MAX_FRAME_BYTES = 8 MiB` guard.
  The JSON `Serialize`/`Deserialize` impls are retained for diagnostics and key
  files but are no longer used on the transport path.

- **Pending queue and nonce persistence (P3)** — `PendingQueue::with_persist(path)`
  atomically persists the approval queue and nonce high-water mark to disk.
  `a2g-gateway --queue-persist <path>` enables persistence. The HWM is loaded
  on startup and used as a post-restart replay gate (receipts from the previous
  session are rejected until the HWM advances). `GatewayState::new_with_queue()`
  exposed for injection in tests and `main`.

- **Adversarial test suite (P2; CI job `adversarial`)** — 10 attacks, each
  mapped to the gateway verification step it targets:
  1. Forbidden bypass, 2. Wrong signing key, 3. Tampered tool post-signing,
  4. Decision field mutation, 5. Nonce replay, 6. Past timestamp,
  7. Future timestamp, 8. Request hash mutation, 9. Phantom binding ID,
  10. CAN state mismatch (ADR-0016 re-gate). CI step: `cargo test -p
  a2g-gateway --test adversarial`.

- **Gateway-side vehicle state ingestion (ADR-0016; P1)**
  — The Enforcing Gateway now subscribes directly to SocketCAN and
  independently re-gates Sensitive-domain enforcement against live bus data.
  - New module `a2g-gateway::state_ingest`: E2E-inspired frame protection
    (CRC-8/SAE-J1850, Profile 1 polynomial 0x1D, over 7 payload bytes + data
    ID; alive counter anti-replay). Speed frame on CAN ID `0x3A0`, gear on
    `0x3A1`. Not a full AUTOSAR-E2E profile implementation.
  - New `bus::CanReader`: Linux-only SocketCAN reader with configurable
    `SO_RCVTIMEO`; returns `Ok(None)` on timeout for non-blocking poll.
  - `GatewayState` gains `state_ingest: Arc<StateIngest>`.
  - `handle_enforce()` re-gates Sensitive tools: fresh gateway state overrides
    the rich domain's claim; mismatch → `REFUSE state_authority_mismatch`.
    No fresh data → warn on `operator_trusted` receipts; pass on `attested`
    (already independently verified by ECU signature).
  - `a2g-gateway --state-ingest` flag activates the background SocketCAN reader.
  - New binary `a2g-state-sim`: broadcasts valid E2E frames at 50 Hz
    (`--vcan`, `--speed-kph`, `--gear`). Used for integration testing and demo.
  - `a2g-core` gains `operator-state` Cargo feature (default on); gates
    `from_operator_trusted()` so production builds can make unattested state a
    compile error.
  - Fail-safe: both signals must be refreshed within `ATTESTATION_FRESHNESS_MS`
    (500 ms) or the ingested state degrades to `speed_mmps=277_500`, gear `Drive`.

### Breaking

- **Binding-signing key moved out of the rich domain into the gateway (ADR-0015)**
  — closes SPEC Appendix A.1 (circular trust assumption). One binding signer in
  the system: `a2g-gateway`.
  - The ephemeral `OnceLock<SigningKey>` is **removed** from `a2g-ffi`. The rich
    domain holds only the gateway's binding *verifying* key.
  - `a2g_decide()` Phase 1 now returns the **unsigned** `PendingApprovalBinding`
    JSON; the host must present it to the gateway's `SignBinding` operation.
  - `a2g_decide_with_approval()` gains a mandatory
    `const uint8_t *binding_pubkey` (32-byte gateway binding verifying key) and
    its `binding_json` parameter is renamed `signed_binding_json` (the
    gateway-signed blob). NULL `binding_pubkey` → `A2G_DECISION_ERROR`
    (fail-explicit, no in-process fallback key).
  - New shared wire type `a2g_core::hitl::SignedBinding` (sign/verify of the
    canonical CBOR `BindingPayload`); the private duplicates in `a2g-ffi` and
    `a2g-gateway` are gone.
  - `DemoKeys` / `GetPublicKeys` gain `binding_verifying_key_hex`.
  - `a2g-gateway --production` now requires `--keystore <path>`; it refuses to
    start without a properly provisioned keystore (SPEC §10.1 Level 3). Dev mode
    still generates ephemeral keys with a loud warning.

- **Issuer trust enforcement added to the decision pipeline (ADR-0014)**
  — `decide()`, `enforce()`, and `decide_with_approval()` in `a2g-core` gain a
  mandatory `trust: &TrustAnchor<'_>` parameter. The FFI ABI gains
  `const A2gTrustAnchorHandle *trust` on `a2g_decide` and
  `a2g_decide_with_approval`; passing NULL returns `A2G_DECISION_ERROR`
  immediately (fail-explicit, no implicit default).
  - New `TrustAnchor<'a>` enum in `a2g_core::enforce`:
    `SelfSovereign` | `Roots(&[[u8;32]])` | `Chain { trusted_roots, chain }`.
  - New FFI constructors: `a2g_trust_anchor_self_sovereign()`,
    `a2g_trust_anchor_roots(pubkeys_flat, count)`.
  - New FFI destructor: `a2g_trust_anchor_free(handle)`.
  - New error variant: `A2gError::IssuerUntrusted`.
  - Enforcement order: forbidden pre-check → Step 0 revocation → Step 1
    signature → **Step 1.5 issuer trust (new)** → Step 2 TTL → Steps 3–7.
  - The Forbidden-domain pre-check still fires before issuer-trust — untrusted
    mandates cannot execute Forbidden-domain tools.
  - `SelfSovereign` is an explicit named opt-in; it is not the default.
  - Three conformance vectors added: `09-issuer-trust/it-001` through `it-003`.

- **Mandate distribution format changed to canonical CBOR (ADR-0013)**
  — mandates compile to signed CBOR for distribution and verification. TOML is the authoring format only (CLI layer). Resolves no_std Blocker #2 (`toml` removed from `a2g-core`).
  - `decide()`, `enforce()`, `decide_with_approval()` now accept `mandate_cbor: &[u8]` instead of `mandate_str: &str`. All call sites updated.
  - FFI ABI: `a2g_decide(const uint8_t *mandate_cbor, size_t mandate_cbor_len, ...)` replaces the former `const char *mandate_toml` parameter. `a2g.h` updated.
  - New CBOR types: `MandateTbs` (33-field positional array, `#[n(0)]`–`#[n(32)]`) and `CborMandate` (`["MANDATE-V1", tbs_bstr, sig_64B, pubkey_32B]`) in `a2g_core::cbor`.
  - Signing: ed25519 over `encode_canonical(&MandateTbs)` bytes (Option b, consistent with BindingPayload/GrantPayload from ADR-0011).
  - `capabilities_hash` (§4.5 SHA-256 of sorted tools joined with `\n`) preserved as `bstr` field in `MandateTbs`; verifier re-derives and checks.
  - `issuer_did` in TBS is verified against `issuer_pubkey` (`did:a2g:<bs58(pubkey)>`).
  - Old TOML mandates are rejected at parse time. Re-sign with `a2g sign`.
  - New CLI module: `a2g-cli/src/mandate_compile.rs` — TOML→CBOR compile+sign path.
  - `toml` dep **removed** from `a2g-core/Cargo.toml` (remains in `a2g-cli`).
  - New public API: `verify_cbor_mandate(cbor: &[u8], now: DateTime<Utc>) -> Result<MandateInfo, A2gError>`.
  - No dual-accept fallback.

- **Unified error type `A2gError` replaces `Box<dyn std::error::Error>` across a2g-core public API (ADR-0012)**
  — `a2g-core` no longer requires `std::error::Error` on the decision path (no_std Blocker #1 resolved).
  - `ApprovalGrantError` enum **removed** from `hitl.rs`. Variants map to `A2gError::BindingMismatch`, `A2gError::GrantExpired`, `A2gError::InvalidKey`, `A2gError::SignatureInvalid`.
  - `AttestationError` enum **removed** from `vehicle.rs`. Variants map to `A2gError::AttestationBadSignature`, `AttestationInvalidKey`, `AttestationStaleNonce`, `AttestationStale`.
  - All fallible public functions in `mandate.rs`, `authority.rs`, `identity.rs`, `proposal.rs`, `receipt.rs`, `enforce.rs`, `ledger.rs`, `hitl.rs`, `vehicle.rs`, `cbor.rs` now return `Result<_, A2gError>`.
  - External `EnforceLedger` implementations must update their return type to `A2gError`; the migration path is `.map_err(|e| A2gError::LedgerError(e.to_string()))`.
  - `std::error::Error` impl is gated behind `#[cfg(feature = "std")]`.
  - No verdict semantics, CBOR wire formats, or signing behavior changes.

- **Wire-format change: colon-delimited signed payloads replaced with canonical CBOR (ADR-0011)**
  — affects `GatewayReceipt` (signed), `PendingApprovalBinding` MAC (gateway + FFI),
  and `ApprovalGrant` signing. Old colon-delimited receipts, bindings, and grants will **not**
  verify against the new code. No dual-accept fallback.
  - `GatewayReceipt::canonical_payload() -> String` replaced by `canonical_bytes() -> Result<Vec<u8>, &'static str>`.
  - `binding_payload()` functions in `server.rs` and `ffi/src/lib.rs` replaced by CBOR byte encoders.
  - `ApprovalGrant::payload_hash()` replaced by `payload_bytes()`; signing is now directly over CBOR bytes (no SHA-256 pre-hash).
  - `ApprovalGrant::new_signed()` now returns `Result<Self, &'static str>` (was `Self`).
  - `ApprovalGrantError::EncodingError` variant added to handle malformed `request_hash` hex.
  - CBOR payload structs: `BindingPayload`, `GrantPayload` in `a2g_core::cbor`; `ReceiptPayload` in `a2g_gateway::protocol`.
  - SPEC §4.5 domain-separator table updated; §7.4 and §9.4 now specify canonical CBOR encoding rules.
  - Note: mandate-CBOR migration is the next task (mandate payload is unchanged).

- **`VehicleState.speed_kph: f64` replaced by `speed_mmps: u32`** — the decision path
  is now float-free (fixed-point determinism, feat/fixed-point-determinism).
  - JSON key in `vehicle_state` params changes from `"speed_kph"` to `"speed_mmps"`.
  - `AttestedVehicleState` signing payload changes (existing attestations must be re-signed).
  - Float speed values are validated and converted at the ingress boundary via
    `speed_kph_to_mmps()`. NaN, ±infinity, negative, subnormal, and values > 1 000 km/h
    are **rejected** (fail-safe DENY at the call site).
  - FFI: `a2g_verified_state_operator_trusted(double speed_kph, ...)` still accepts
    `double` at the C ABI, but now returns NULL for invalid floats.
  - Gate threshold: `speed_mmps < 1 389` (≡ `speed_kph < 5.0`).
  - Fail-safe: `speed_mmps = 277 500` (≡ 999 km/h).
  - SPEC §6.8 normatively specifies the encoding and boundary-rejection rule.
  - Verdict semantics for all valid in-range speeds are unchanged.

- **Mandate signing payload changed to SPEC §4.5 canonical format** (breaking protocol change).
  The signing payload is now `MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>`
  where `capabilities_hash = SHA-256(tools sorted lexicographically, joined with `\n`)`.
  Previously the payload was `MANDATE:<re-serialized-toml-body>`.
  All mandates signed before this change will fail signature verification and must be re-signed
  with `a2g sign`. No dual-accept fallback is provided — one canonical format, the spec's.

- `a2g sign` without `--proposal` or `--skip-proposal` now exits non-zero with a guidance message
  instead of silently signing in backwards-compatible mode. Callers must supply one of:
  - `--proposal <file>` — full governance verification (proposal hash, status, expiry)
  - `--skip-proposal` — explicit governance exception with a stderr warning

## [0.1.0] - 2026-03-29

### Added

- 8-step enforcement pipeline for agent-to-governance compliance.
- Ed25519 digital signatures for action verification.
- Hash-chained audit ledger for tamper-evident logging.
- Delegation chains with scoped authority propagation.
- Proposal-review workflow for human-in-the-loop governance.
- 5 framework integrations (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Claude Agent SDK).
- Trust compression for efficient credential verification.
- Execution lineage tracking across multi-agent workflows.
- Visual receipts for human-readable compliance evidence.
- Declarative policy tests for governance rule validation.
