package ai.vanaras.a2g

/**
 * Base class for all A2G SDK exceptions.
 *
 * A2G exceptions are thrown for programming errors at the SDK boundary —
 * missing required inputs, reserved names, or safety-critical invariant
 * violations. They are NOT thrown for DENY verdicts; DENY is a normal
 * protocol outcome returned as [Verdict.Deny].
 */
open class A2gException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * Thrown when [A2g.decide] or [A2g.decideWithApproval] is called before
 * [A2g.init] has been called.
 */
class A2gNotInitializedException :
    A2gException("A2g.init() must be called before decide()")

/**
 * Thrown when a null or incorrect-length binding public key is supplied to
 * [A2g.decideWithApproval].
 *
 * This directly maps to the C ABI fail-explicit behavior: passing NULL for
 * binding_pubkey returns A2G_DECISION_ERROR (ADR-0015). The SDK surfaces this
 * as a typed exception so callers cannot ignore it.
 *
 * DO NOT catch and swallow this exception — it indicates a provisioning error.
 */
class A2gNullPubkeyException(detail: String) :
    A2gException("bindingPubkey must be 32 non-null bytes (ADR-0015): $detail")

/**
 * Thrown when [A2g.decide] is called with the reserved sentinel name "pii.grant".
 *
 * SPEC §3.6.3: "pii.grant" is a capability sentinel, not a callable tool.
 * Invoking it as a tool MUST produce DENY at the SDK layer before any JNI call.
 * This exception surfaces that structural refusal so callers see a clear error
 * rather than an opaque Deny verdict.
 */
class PiiGrantReservedNameException :
    A2gException(
        "\"pii.grant\" is a reserved capability sentinel (SPEC §3.6.3) and cannot " +
            "be called as a tool. This string signals PII access in a mandate's " +
            "capabilities.tools list; it does not name an executable action."
    )

/**
 * Thrown when an internal JNI error occurs and the native library cannot return
 * a verdict (e.g., panic caught, invalid UTF-8, or encoding failure).
 *
 * This corresponds to A2G_DECISION_ERROR from the C ABI.
 */
class A2gInternalErrorException(detail: String) :
    A2gException("Internal A2G error: $detail")
