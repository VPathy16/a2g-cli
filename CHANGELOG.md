# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

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
