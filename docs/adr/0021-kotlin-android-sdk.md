# ADR-0021 — Kotlin Android SDK: a2g-ffi Wrapper for AAOS App Developers

**Status:** Accepted  
**Date:** 2026-06-12  
**Replaces:** —  
**Related:** ADR-0009 (FFI C-ABI), ADR-0014 (issuer trust), ADR-0015 (binding key custody),
ADR-0016 (gateway state ingest), ADR-0017 (comfort context), ADR-0018 (cockpit domains),
SPEC §3.6 (pii.grant reserved sentinel), SPEC §9 (enforcement contract)

---

## Context

AAOS (Android Automotive OS) in-cabin agents need a safe, idiomatic Kotlin API to
govern tool calls through A2G before they reach CarPropertyManager or cockpit
services. The existing C ABI (`a2g-ffi`, ADR-0009) is correct and frozen but is
not ergonomic for Kotlin/Android developers:

- Opaque C handles require explicit memory management.
- `A2gDecision` integers must be mapped to application-layer meaning manually.
- The binding/grant lifecycle (Phase 1 → gateway SignBinding → Phase 2) is hard
  to use correctly without a state machine.
- The CBOR-framed gateway socket protocol has no Kotlin implementation.

### Threat model (rich domain)

The Android SDK runs in the AAOS rich domain — the same trust tier as any other
application process. It can lie. The Enforcing Gateway (a2g-gateway, SPEC §9)
remains the sole enforcement point. The SDK's role is:

1. Wrap the a2g-ffi C ABI cleanly and safely via JNI.
2. Implement the CBOR-framed Unix socket client for gateway communication.
3. Ensure the pii.grant reserved-name rule (SPEC §3.6.3) is structurally
   enforced at the SDK layer before any JNI call.
4. Surface ADR-0015 null-pubkey fail-explicit behavior as a Kotlin exception,
   never as a silent default.
5. Provide a GovernedCarClient sample that shows how to wrap CarPropertyManager
   so every actuation call goes through decide() + enforce() first.

Because the SDK is rich-domain, a compromised SDK process cannot bypass the
gateway's independent 7-step verification. The protocol is frozen; this SDK
adds only a Kotlin convenience layer above the existing C ABI.

---

## Decision

### Module layout

```
sdk/android/
  a2g/                     — library module
    src/main/kotlin/ai/vanaras/a2g/
      A2g.kt               — top-level init/decide API + JNI declarations
      Verdict.kt           — Verdict sealed class + ReasonCode enum
      TrustAnchor.kt       — Kotlin TrustAnchor → a2g_trust_anchor_* FFI
      GatewayClient.kt     — CBOR-framed Unix socket transport
      A2gException.kt      — typed exceptions surfacing FFI fail-explicit errors
    src/main/jniLibs/      — populated by cargo-ndk at build time
    build.gradle.kts
  sample/                  — GovernedCarClient + demo activity
    src/main/kotlin/ai/vanaras/a2g/sample/
      GovernedCarClient.kt
      DemoActivity.kt
    build.gradle.kts
  build.gradle.kts         — root aggregation
  settings.gradle.kts
  gradle/
  gradlew / gradlew.bat
  README.md
```

### JNI strategy

All JNI declarations are `external fun` in a companion object inside a Kotlin
`object` (singleton). The JNI glue is implemented in Kotlin using `System.loadLibrary`.

For host unit tests (JVM, not Android), a `MockJniBridge` replaces the native
library. The mock faithfully simulates the real behavior:
- DENY on forbidden tools (vehicle domain, pii.profile.export).
- DENY on pii.grant invoked as a tool (SPEC §3.6.3 reserved name).
- DENY on tool not in mandate.
- NULL-pubkey → throws `A2gNullPubkeyException` (fail-explicit, ADR-0015).
- The mock MUST NOT silently default to ALLOW.

### API surface

```kotlin
// Initialization
object A2g {
    fun init(mandateCbor: ByteArray, trustAnchor: TrustAnchor)
    fun decide(tool: String, paramsJson: String): Verdict
    fun decideWithApproval(
        tool: String, paramsJson: String,
        signedBindingJson: String, bindingPubkey: ByteArray,
        grantJson: String
    ): Verdict
}

// Verdict
sealed class Verdict {
    data class Allow(val receipt: String, val verdictId: String) : Verdict()
    data class Deny(val reasonCode: ReasonCode, val humanText: String) : Verdict()
    data class Escalate(val binding: String, val bindingId: String) : Verdict()
}

// ReasonCode enum — mirrors a2g-core reason codes (must be kept in sync)
enum class ReasonCode {
    MANDATE_INVALID, MANDATE_TTL_EXCEEDED, TOOL_NOT_AUTHORIZED,
    BOUNDARY_VIOLATION, VEHICLE_STATE_VIOLATION, VEHICLE_FORBIDDEN_DOMAIN,
    COCKPIT_FORBIDDEN_DOMAIN, JURISDICTION_VIOLATION, RATE_LIMIT_EXCEEDED,
    MANDATE_REVOKED, ISSUER_UNTRUSTED, INVALID_REQUEST, PII_GRANT_REQUIRED,
    INTERNAL_ERROR, UNKNOWN
}

// Trust anchor
sealed class TrustAnchor {
    object SelfSovereign : TrustAnchor()
    data class Roots(val pubkeys: List<ByteArray>) : TrustAnchor()
}
```

### pii.grant reserved-name enforcement (SPEC §3.6.3)

The SDK checks `tool == "pii.grant"` before any JNI call in `A2g.decide()`.
If the check fires, a `PiiGrantReservedNameException` is thrown. This is
structurally first — independent of the native library. The JNI path is never
reached for this input.

Rationale: SPEC §3.6.3 states the sentinel produces no side-effectful dispatch.
An SDK-layer structural check is defense-in-depth; the core still denies it, but
Kotlin callers see a clear exception rather than a Deny verdict with an opaque
policy_rule.

### ADR-0015 null-pubkey behavior

`A2g.decideWithApproval()` requires `bindingPubkey` to be non-null and exactly
32 bytes. If either check fails, `A2gNullPubkeyException` is thrown before the
JNI call. This matches the C ABI behavior (NULL → A2G_DECISION_ERROR) but
surfaces it as a typed Kotlin exception for IDE-level feedback.

### GatewayClient transport

`GatewayClient` speaks the same CBOR-framed Unix socket protocol as
`a2g-gateway/src/transport.rs`:
- Frame layout: `[u32 BE length][ciborium CBOR body]`
- Max frame: 64 KiB
- Messages: `GatewayRequest` / `GatewayResponse` (same tag strings as the Rust
  structs, matching the serde-derived JSON tag names for CBOR compatibility)

The client is behind a `GatewayTransport` interface with a `UnixSocketTransport`
default implementation. A `VsockTransport` is documented as the extension point
for hypervisor-isolated deployments (future).

### cargo-ndk build

The `a2g` library Gradle module includes a custom build task that runs:
```
cargo ndk -t arm64-v8a -t x86_64 build --release
```
targeting `crates/a2g-ffi`. The resulting `.so` files are copied to
`a2g/src/main/jniLibs/{arm64-v8a,x86_64}`.

If `cargo-ndk` is not installed, the task prints a clear error message and the
build fails loudly — it does not silently produce a broken library.

For CI, the Kotlin SDK build is done in a separate `android-sdk` job that
installs the Android SDK, NDK, and cargo-ndk before building.

### ReasonCode sync test

A unit test in `a2g/src/test/kotlin/` reads the known policy_rule prefixes from
a static list and asserts that every ReasonCode maps to at least one prefix. This
prevents drift between the Kotlin enum and the Rust policy_rule strings.

---

## Consequences

### Added

- `sdk/android/` — new Gradle multi-project at the repo root. Not a Cargo
  workspace member. No Rust crate changes except one justified pub addition (below).
- `docs/adr/0021-kotlin-android-sdk.md` — this document.
- CI job `android-sdk` in `.github/workflows/ci.yml`.
- `CHANGELOG [Unreleased] — Added (S3)` entry.

### Rust crate changes (justified)

- `a2g-ffi`: no source changes required. The JNI glue in Kotlin calls the
  existing `a2g_decide`, `a2g_decide_with_approval`, and `a2g_trust_anchor_*`
  symbols directly. The ABI is frozen (ADR-0009).

### Not changed

- `a2g-core`: no changes.
- `a2g-gateway`: no changes.
- The protocol is FROZEN: no changes to `MandateTbs`, `CborMandate`, signed
  payload layouts, or verdict semantics.

### Open questions

- **VsockTransport**: hypervisor-partition deployment (AAOS Safety Island) needs
  AF_VSOCK instead of AF_UNIX. The `GatewayTransport` interface is the seam.
  Implementation is out of scope for S3.
- **AttestationVerification**: the AAOS HAL attestation path (ECU-signed state,
  SPEC §6.4) needs a dedicated Android API. For S3, only operator-trusted state
  is exposed via `A2g.createVehicleState()`. Full attestation is out of scope.
- **Keystore integration**: in production AAOS deployments, the binding verifying
  key should be provisioned in the Android Keystore. For S3, the key is passed
  as a raw ByteArray. Keystore integration is out of scope.
