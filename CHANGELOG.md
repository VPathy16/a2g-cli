# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

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
