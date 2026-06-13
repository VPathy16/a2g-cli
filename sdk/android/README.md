# A2G Android SDK

Kotlin library wrapping [`a2g-ffi`](../../crates/a2g-ffi) for AAOS app developers,
plus a `GovernedCarClient` sample showing the ALLOW / DENY / ESCALATE governance flow.

**ADR-0021** | **v0.2.0+** | **minSdk 29** (Android 10 / AAOS)

---

## Quick start: clone to first DENY in under 30 minutes

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Android Studio | Hedgehog+ | https://developer.android.com/studio |
| Android NDK | 26.x LTS | SDK Manager → NDK (Side by side) |
| Rust stable | 1.77+ | `rustup update stable` |
| cargo-ndk | 3.5+ | `cargo install cargo-ndk` |
| Android targets | — | `rustup target add aarch64-linux-android x86_64-linux-android` |

### Step 1 — Build the native library

From the **repo root**:

```bash
cd /path/to/a2g-cli

# Build liba2g_ffi.so for arm64-v8a and x86_64
cargo ndk -t arm64-v8a -t x86_64 build --release -p a2g-ffi

# The .so files land at:
#   target/aarch64-linux-android/release/liba2g_ffi.so
#   target/x86_64-linux-android/release/liba2g_ffi.so
```

The Gradle `cargoBuildFfi` task copies these into `sdk/android/a2g/src/main/jniLibs/`
automatically when you build the library module.

### Step 2 — Generate a test mandate

```bash
# Generate a demo mandate with climate + window tools
./target/release/a2g sign \
    --agent-name "demo-agent" \
    --tools vehicle.climate.set_temperature,vehicle.window.set_position \
    --ttl 24h \
    --skip-proposal \
    --out demo_mandate.cbor

# Copy to the sample assets directory
cp demo_mandate.cbor sdk/android/sample/src/main/assets/
```

### Step 3 — Start the gateway

```bash
./target/release/a2g-gateway \
    --socket /tmp/a2g_demo.sock \
    --dev-mode
# Gateway prints its demo key file path — note it for Step 4
```

### Step 4 — Build and run on the AAOS emulator

```bash
cd sdk/android

# Generate gradle wrapper (first time only)
gradle wrapper --gradle-version 8.7

# Build library + sample
./gradlew :a2g:assemble :sample:assemble

# Install on emulator (with AAOS system image)
./gradlew :sample:installDebug

# Launch the demo activity
adb shell am start -n ai.vanaras.a2g.sample/.DemoActivity
```

### Step 5 — Expected behavior

| Button | Tool | A2G Verdict | UI Badge |
|--------|------|-------------|----------|
| Climate 22°C | vehicle.climate.set_temperature | ALLOW | Green |
| Window 50% (vehicle stopped) | vehicle.window.set_position | ALLOW | Green |
| Window 50% (vehicle moving) | vehicle.window.set_position | DENY (state_violation) | Red |
| Cruise Control | CRUISE_CONTROL_COMMAND | DENY (vehicle_forbidden_domain) | Dark Red |
| Send SMS | comms.sms.send | ESCALATE (always-HITL) | Amber |

**First DENY**: tap the "Window" button while the demo gateway has a vehicle
state showing speed > 5 km/h. The status panel shows:
> "DENY ✗ — This action is not permitted while the vehicle is in its current state."

---

## API reference

### A2g (object)

```kotlin
// Initialize with a signed CBOR mandate and trust anchor
A2g.init(mandateCbor: ByteArray, trustAnchor: TrustAnchor)

// Phase 1 decision
A2g.decide(tool: String, paramsJson: String): Verdict

// Phase 2 decision (after human approval)
A2g.decideWithApproval(
    tool: String, paramsJson: String,
    signedBindingJson: String,
    bindingPubkey: ByteArray,   // 32 bytes — MUST NOT be empty (ADR-0015)
    grantJson: String,
): Verdict
```

### Verdict (sealed class)

```kotlin
when (verdict) {
    is Verdict.Allow   -> {
        // Present verdict.receipt to gateway.enforce() before acting
        gatewayClient.enforce(parseReceipt(verdict.receipt))
        // Then perform the action
    }
    is Verdict.Deny    -> {
        // verdict.reasonCode is machine-readable (switch on ReasonCode enum)
        // verdict.humanText is suitable for assistant speech / UI
        tts.speak(verdict.humanText)
    }
    is Verdict.Escalate -> {
        // Phase 1 HITL: present unsigned binding to gateway for signing
        val signedBinding = gatewayClient.signBinding(verdict.unsignedBindingJson)
        // Then await operator approval (SubmitGrant flow)
        // Then call A2g.decideWithApproval(...)
    }
}
```

### ReasonCode enum

All reason codes that a2g-core can produce. Used for programmatic handling
(routing to different error UI, logging, metrics).

```kotlin
ReasonCode.MANDATE_INVALID          // Bad signature
ReasonCode.MANDATE_TTL_EXCEEDED     // Expired
ReasonCode.TOOL_NOT_AUTHORIZED      // Not in mandate
ReasonCode.BOUNDARY_VIOLATION       // Path/network/command denied
ReasonCode.VEHICLE_STATE_VIOLATION  // Speed gate failed
ReasonCode.VEHICLE_FORBIDDEN_DOMAIN // Structural safety refusal
ReasonCode.COCKPIT_FORBIDDEN_DOMAIN // pii.profile.export
ReasonCode.JURISDICTION_VIOLATION   // Operating hours
ReasonCode.RATE_LIMIT_EXCEEDED      // Too many calls
ReasonCode.MANDATE_REVOKED          // Ledger revocation
ReasonCode.ISSUER_UNTRUSTED         // ADR-0014 root check
ReasonCode.INVALID_REQUEST          // Empty tool name
ReasonCode.PII_GRANT_REQUIRED       // ADR-0018 sentinel missing
ReasonCode.INTERNAL_ERROR           // FFI panic / encoding error
ReasonCode.UNKNOWN                  // SDK out of sync (update ReasonCode)
```

### GatewayClient

```kotlin
val client = GatewayClient(UnixSocketTransport("/tmp/a2g.sock"))

// Sign a Phase 1 binding (HITL flow)
val signedBinding = client.signBinding(verdict.unsignedBindingJson)

// Enforce an ALLOW verdict (bus-write authorization)
val result = client.enforce(receipt)

// Bootstrap: get gateway public keys
val keys = client.getPublicKeys()
val bindingPubkey = hexDecode(keys.bindingVerifyingKeyHex)
```

---

## OEM localisation

The `ReasonCode → user-facing string` contract is defined in
`a2g/src/main/res/values/strings.xml`. Each string resource is named
`a2g_reason_<REASON_CODE_LOWER_CASE>`.

To localise:
1. Copy `res/values/strings.xml` to `res/values-<locale>/strings.xml`.
2. Translate each string. **Do not rename the resource IDs.**
3. The `DemoActivity.reasonCodeToStringRes()` function uses these IDs.

Example for German:
```xml
<!-- res/values-de/strings.xml -->
<string name="a2g_reason_vehicle_forbidden_domain">
    Diese Aktion betrifft ein sicherheitskritisches Fahrzeugsystem und kann
    unter keinen Umständen durch einen automatisierten Assistenten ausgeführt werden.
</string>
```

---

## Security notes

- The SDK runs in the AAOS rich domain. It **cannot** bypass the Enforcing
  Gateway's 7-step verification (SPEC §9.5, ADR-0010).
- `A2g.decideWithApproval()` requires a 32-byte `bindingPubkey`. Passing
  any other length throws `A2gNullPubkeyException` immediately — the native
  layer is never called. This is the ADR-0015 fail-explicit behavior.
- `pii.grant` is a reserved capability sentinel (SPEC §3.6.3). Calling
  `A2g.decide("pii.grant", ...)` throws `PiiGrantReservedNameException`
  before any JNI call. The SDK never dispatches this string as an action.

---

## CI cross-build

The `android-sdk` CI job in `.github/workflows/ci.yml`:
1. Installs Android SDK + NDK + cargo-ndk.
2. Runs `cargo ndk` to build `liba2g_ffi.so` for arm64-v8a and x86_64.
3. Runs `./gradlew :a2g:assemble :sample:assemble`.
4. Runs host-JVM unit tests: `./gradlew :a2g:test`.

Host unit tests do not require a device or the native library — they use
`MockJniBridge` which simulates the real behavior faithfully.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  AAOS App (GovernedCarClient / DemoActivity)             │
│  ┌────────────────────────────────────────────────────┐  │
│  │  A2g.decide(tool, params)   → Verdict              │  │
│  │  A2g.decideWithApproval(…)  → Verdict              │  │
│  └────────────────────────────────────────────────────┘  │
│          │ JNI (liba2g_ffi.so)                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │  a2g-ffi (Rust C ABI)                              │  │
│  │  a2g-core decision engine (pure, no I/O)           │  │
│  └────────────────────────────────────────────────────┘  │
│          │ CBOR-framed Unix socket (GatewayClient)       │
└──────────┼───────────────────────────────────────────────┘
           │
┌──────────┴──────────────────────────────────────────────┐
│  a2g-gateway (separate trust domain — SPEC §9.2)        │
│  7-step independent verification → vehicle bus write     │
└─────────────────────────────────────────────────────────┘
```

The gateway cannot be bypassed by a compromised SDK or app process.
See ADR-0010 (enforcing gateway) and SPEC §9 (enforcement contract).
