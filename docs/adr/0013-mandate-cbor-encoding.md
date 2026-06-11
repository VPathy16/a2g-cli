# ADR-0013: Canonical CBOR Distribution Format for Mandates

**Status:** Accepted  
**Date:** 2026-06-10  
**Resolves:** no_std Blocker #2 (`toml` crate on the core decision path)

---

## Context

Mandates are the signed policy documents that authorise agent actions. Before this ADR, mandates were serialised as TOML strings and passed directly to `decide()` / `enforce()`. This created two problems:

1. **no_std Blocker #2**: the `toml` crate (v0.8) requires `std` (uses `HashMap`, `std::io`). `a2g-core` could not be built `no_std` while `toml` remained on the decision path.
2. **Wire-format inconsistency**: receipts and approval grants already used canonical CBOR (ADR-0011), but mandates still used TOML — an inconsistency in the signed-payload family.

---

## Decision: Option (b) — Signature over `encode_canonical(&MandateTbs)` bytes

Two signing options were considered:

### Option (a) — Colon-delimited canonical string (§4.5)
Sign the string `MANDATE:<agent_did>:<issuer_did>:<expires_at>:<capabilities_hash>`.  
**Rejected**: inconsistent with how BindingPayload and GrantPayload are signed (both sign CBOR bytes, not strings). Mixed signing surfaces create confusion and risk.

### Option (b) — Signature over CBOR TBS bytes ✓
Sign `encode_canonical(&MandateTbs)` using ed25519. Consistent with BindingPayload and GrantPayload (ADR-0011). One unified signing contract: **always sign canonical CBOR bytes**.

---

## Wire Format

### `MandateTbs` — to-be-signed content

Positional CBOR array (`#[cbor(array)]`), 33 fields (`#[n(0)]`–`#[n(32)]`).  
Field order is normative; positions must not change.

```
[
  "MANDATE",         // tag
  agent_did,
  issuer_did,
  agent_name,
  issued_at,         // RFC 3339
  expires_at,        // RFC 3339
  proposal_hash,
  workspace_root,
  capabilities_hash, // bstr 32B (SHA-256, §4.5 algorithm preserved)
  tools,             // [tstr]
  fs_read,           // [tstr]
  fs_write,          // [tstr]
  fs_deny,           // [tstr]
  net_allow,         // [tstr]
  net_deny,          // [tstr]
  cmd_allow,         // [tstr]
  cmd_deny,          // [tstr]
  max_calls_per_minute,     // uint
  max_file_size_bytes,      // uint
  max_output_tokens,        // uint
  max_session_duration_sec, // uint
  deny_patterns,     // [tstr]
  redact_patterns,   // [tstr]
  max_output_length, // uint
  region,            // tstr
  regulatory_framework, // tstr
  environment,       // tstr
  classification,    // tstr
  operating_hours,   // tstr
  escalate_tools,    // [tstr]
  escalate_paths,    // [tstr]
  escalate_hosts,    // [tstr]
  escalate_to,       // tstr
]
```

### `CborMandate` — distribution envelope

```
["MANDATE-V1", tbs_cbor(bstr), signature(bstr 64B), issuer_pubkey(bstr 32B)]
```

- `tbs_cbor`: `encode_canonical(&MandateTbs)` bytes
- `signature`: ed25519 signature over `tbs_cbor`
- `issuer_pubkey`: 32-byte ed25519 verifying key

### `capabilities_hash` field

SHA-256 of tools sorted lexicographically (UTF-8 byte order), joined with `\n`. Same algorithm as specified in SPEC §4.5. Encoded as a 32-byte CBOR `bstr` in `MandateTbs[8]`.

Verification re-derives the hash from `tools` and compares against `capabilities_hash`. Mismatch → `A2gError::MandateInvalid`.

### `issuer_did` field

`did:a2g:<bs58(issuer_pubkey)>`. Verification checks this field matches the `issuer_pubkey` in the envelope. Mismatch → `A2gError::MandateInvalid`.

---

## Compile and Verify Paths

### Compile (CLI layer only, `a2g sign`)

1. Parse TOML mandate template (`a2g-cli/src/mandate_compile.rs`; `toml` dep stays in CLI).
2. Compute `capabilities_hash` from sorted tools.
3. Construct `MandateTbs`.
4. `tbs_bytes = encode_canonical(&tbs)`.
5. `sig = ed25519.sign(tbs_bytes)` using issuer's secret key.
6. Construct `CborMandate { "MANDATE-V1", tbs_bytes, sig, issuer_pubkey }`.
7. Write `encode_canonical(&envelope)` bytes as the `.mandate` file.

### Verify (a2g-core, zero-copy capable)

1. `decode_canonical::<CborMandate>(cbor)` — tag check ("MANDATE-V1").
2. `decode_canonical::<MandateTbs>(&envelope.tbs)` — tag check ("MANDATE").
3. ed25519 verify: `verifying_key.verify(&envelope.tbs, &sig)`.
4. Re-derive `issuer_did`; compare with `tbs.issuer_did`.
5. Re-derive `capabilities_hash`; compare with `tbs.capabilities_hash`.
6. TTL check: `expires_at > now`.

### Pipeline order in `decide_core()`

- **Step 0** (revocation): `parse_cbor_mandate_raw()` — decodes envelope **without** sig verification. Extracts `agent_did` for ledger lookup. `mandate_hash = SHA-256(mandate_cbor)`.
- **Step 1** (signature): `verify_cbor_signature()` — full verification as above.

---

## Breaking Changes

- **`decide()` / `enforce()` / `decide_with_approval()`** now accept `mandate_cbor: &[u8]` instead of `mandate_str: &str`. All call sites updated.
- **FFI ABI**: `a2g_decide(const uint8_t *mandate_cbor, size_t mandate_cbor_len, ...)` replaces the former `const char *mandate_toml` parameter. The C header `a2g.h` is updated accordingly.
- **`a2g sign`** now writes a binary `.mandate` file (CBOR) instead of TOML.
- **`a2g verify` / `a2g enforce`** now read binary CBOR mandate files.
- Old TOML mandates will be rejected at parse time. All mandates must be recompiled with `a2g sign`.
- No dual-accept fallback.

---

## no_std Status After This ADR

| Blocker | Status |
|---------|--------|
| `Box<dyn std::error::Error>` | **RESOLVED** (ADR-0012) |
| `toml` crate | **RESOLVED** (this ADR) — removed from `a2g-core/Cargo.toml` |
| `regex` crate | Open — blocker #3 |
| `uuid` OsRng | Open — blocker #4 |
| `std::sync::Mutex` receipt | Open — blocker #5 |
