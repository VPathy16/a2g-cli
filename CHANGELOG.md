# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

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
