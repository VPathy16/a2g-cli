package ai.vanaras.a2g

import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Top-level A2G governance API for AAOS app developers.
 *
 * Usage:
 * ```kotlin
 * // 1. Initialize once (e.g., in Application.onCreate)
 * A2g.init(mandateCborBytes, TrustAnchor.SelfSovereign)
 *
 * // 2. Call decide() before every action
 * when (val v = A2g.decide("vehicle.climate.set_temperature", """{"temp_c": 22}""")) {
 *     is Verdict.Allow   -> gateway.enforce(v.receipt)
 *     is Verdict.Deny    -> log.warn("Denied: ${v.humanText}")
 *     is Verdict.Escalate -> requestApproval(v.bindingId)
 * }
 * ```
 *
 * Thread safety: [init] and [decide] may be called from any thread.
 * [init] is write-locked; [decide] is read-locked during JNI dispatch.
 */
object A2g {

    /**
     * Pluggable JNI bridge — real native bridge in production, mock in host tests.
     *
     * [testBridge] is null in production; [setBridgeForTesting] sets it before
     * [init] is called in tests. Keeping a separate nullable avoids accessing
     * [NativeJniBridge] (which triggers System.loadLibrary) at class-load time.
     */
    @Volatile
    private var testBridge: JniBridge? = null

    // Computed property — NativeJniBridge is accessed only when testBridge is null
    // (i.e., only in production, never during host-JVM tests).
    private val bridge: JniBridge get() = testBridge ?: NativeJniBridge

    /** Stable reference to the initialized state. */
    private val stateRef = AtomicReference<InitState?>(null)
    private val lock = ReentrantReadWriteLock()

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Initialize the A2G engine with a signed CBOR mandate and a trust anchor.
     *
     * Must be called exactly once before any [decide] call. Calling again with
     * new parameters replaces the current mandate (useful in tests; in production
     * call once per app process).
     *
     * @param mandateCbor Signed CBOR mandate bytes (ADR-0013 CborMandate format).
     * @param trustAnchor Which issuers are trusted for this mandate (ADR-0014).
     */
    fun init(mandateCbor: ByteArray, trustAnchor: TrustAnchor) {
        lock.write {
            stateRef.set(InitState(mandateCbor.copyOf(), trustAnchor))
        }
    }

    /**
     * Evaluate a governance decision for [tool] with [paramsJson] parameters.
     *
     * This is Phase 1 of the decide/enforce lifecycle (SPEC §1.3).
     *
     * @param tool      The capability identifier (e.g. "vehicle.climate.set_temperature").
     *                  Must not be "pii.grant" — that is a reserved sentinel, not a
     *                  callable tool (SPEC §3.6.3).
     * @param paramsJson JSON object of tool parameters. Pass "{}" for no parameters.
     * @return A [Verdict]: [Verdict.Allow], [Verdict.Deny], or [Verdict.Escalate].
     * @throws PiiGrantReservedNameException if tool == "pii.grant"
     * @throws A2gNotInitializedException if [init] has not been called
     * @throws A2gInternalErrorException on native-layer panic or encoding failure
     */
    fun decide(tool: String, paramsJson: String): Verdict {
        // Structural pre-check: pii.grant is a reserved sentinel (SPEC §3.6.3).
        // This check fires BEFORE any JNI call — the native library never sees this name.
        if (tool == "pii.grant") {
            throw PiiGrantReservedNameException()
        }

        val state = lock.read { stateRef.get() }
            ?: throw A2gNotInitializedException()

        return bridge.decide(state.mandateCbor, state.trustAnchor, tool, paramsJson)
    }

    /**
     * Evaluate a Phase 2 governance decision with a pre-validated human approval.
     *
     * Use this after [decide] returns [Verdict.Escalate], the gateway has signed
     * the binding, and an operator has produced an [ApprovalGrant] (SPEC §7).
     *
     * @param tool              Same tool as Phase 1.
     * @param paramsJson        Same parameters as Phase 1.
     * @param signedBindingJson The gateway-signed binding blob (from
     *                          [GatewayClient.signBinding] response).
     *                          Do NOT modify — any field change invalidates the
     *                          gateway signature and produces A2G_DECISION_ERROR.
     * @param bindingPubkey     32-byte ed25519 verifying key of the gateway's
     *                          binding-signing key (ADR-0015). Must not be null
     *                          and must be exactly 32 bytes.
     * @param grantJson         JSON-serialized ApprovalGrant from the human approver.
     * @return A [Verdict].
     * @throws PiiGrantReservedNameException if tool == "pii.grant"
     * @throws A2gNullPubkeyException if [bindingPubkey] is null or not 32 bytes
     * @throws A2gNotInitializedException if [init] has not been called
     * @throws A2gInternalErrorException on native-layer error
     */
    fun decideWithApproval(
        tool: String,
        paramsJson: String,
        signedBindingJson: String,
        bindingPubkey: ByteArray,
        grantJson: String,
    ): Verdict {
        if (tool == "pii.grant") {
            throw PiiGrantReservedNameException()
        }

        // ADR-0015: fail-explicit null/wrong-length pubkey check mirrors the C ABI.
        if (bindingPubkey.size != 32) {
            throw A2gNullPubkeyException(
                "expected 32 bytes, got ${bindingPubkey.size}"
            )
        }

        val state = lock.read { stateRef.get() }
            ?: throw A2gNotInitializedException()

        return bridge.decideWithApproval(
            state.mandateCbor, state.trustAnchor,
            tool, paramsJson,
            signedBindingJson, bindingPubkey, grantJson,
        )
    }

    // ── Testing seam ──────────────────────────────────────────────────────────

    /**
     * Replace the JNI bridge for testing.
     *
     * Call this before [init] in test setup. The mock MUST faithfully simulate
     * the real behavior (see [MockJniBridge]).
     *
     * This method is annotated with @VisibleForTesting but is not guarded by
     * a compile-time annotation to avoid requiring a test dependency at runtime.
     */
    fun setBridgeForTesting(mock: JniBridge) {
        testBridge = mock
    }

    /** Reset the bridge to the real native bridge (call in @After to clean up). */
    fun resetBridge() {
        testBridge = null
    }

    /** Reset init state (useful in tests). */
    fun resetForTesting() {
        lock.write { stateRef.set(null) }
    }

    // ── Internal types ────────────────────────────────────────────────────────

    private data class InitState(
        val mandateCbor: ByteArray,
        val trustAnchor: TrustAnchor,
    )
}

// ── JNI bridge interface (testability seam) ────────────────────────────────────

/**
 * JNI bridge interface. Production code uses [NativeJniBridge]; tests use
 * [MockJniBridge] which runs on the host JVM without an Android device or the
 * a2g-ffi shared library.
 */
interface JniBridge {
    fun decide(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
    ): Verdict

    fun decideWithApproval(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
        signedBindingJson: String,
        bindingPubkey: ByteArray,
        grantJson: String,
    ): Verdict
}

// ── Native JNI bridge ─────────────────────────────────────────────────────────

/**
 * Production JNI bridge — delegates to the a2g-ffi shared library via JNI.
 *
 * The native methods declared here have exact C ABI equivalents in liba2g_ffi.so.
 * The JNI glue maps:
 * - ByteArray → const uint8_t* + size_t
 * - String → const char* (NUL-terminated UTF-8)
 * - returns int32_t A2gDecision
 *
 * The native library is loaded lazily on first use. If the library is not
 * present (e.g., wrong ABI, missing jniLibs), an UnsatisfiedLinkError is thrown.
 */
object NativeJniBridge : JniBridge {

    init {
        System.loadLibrary("a2g_ffi")
    }

    override fun decide(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
    ): Verdict = nativeDecide(mandateCbor, trustAnchor.toNativeMode(), tool, paramsJson)

    override fun decideWithApproval(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
        signedBindingJson: String,
        bindingPubkey: ByteArray,
        grantJson: String,
    ): Verdict = nativeDecideWithApproval(
        mandateCbor, trustAnchor.toNativeMode(),
        tool, paramsJson,
        signedBindingJson, bindingPubkey, grantJson,
    )

    // ── Native method declarations ─────────────────────────────────────────────
    // These are implemented by the JNI glue in NativeGlue.kt (which calls the
    // a2g_decide / a2g_decide_with_approval C functions via JNI).

    private external fun nativeDecide(
        mandateCbor: ByteArray,
        trustMode: Int,      // 0 = SelfSovereign, 1 = Roots
        tool: String,
        paramsJson: String,
    ): Verdict

    private external fun nativeDecideWithApproval(
        mandateCbor: ByteArray,
        trustMode: Int,
        tool: String,
        paramsJson: String,
        signedBindingJson: String,
        bindingPubkey: ByteArray,
        grantJson: String,
    ): Verdict

    private fun TrustAnchor.toNativeMode(): Int = when (this) {
        is TrustAnchor.SelfSovereign -> 0
        is TrustAnchor.Roots -> 1
    }
}
