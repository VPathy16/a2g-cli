package ai.vanaras.a2g

/**
 * The governance verdict returned by [A2g.decide].
 *
 * No C types are exposed; the sealed class hierarchy is idiomatic Kotlin.
 *
 * ADR-0021 mapping from A2G protocol to Kotlin:
 * - A2G_DECISION_ALLOW         → [Allow]
 * - A2G_DECISION_DENY          → [Deny]
 * - A2G_DECISION_EXPIRED       → [Deny] with reasonCode = MANDATE_TTL_EXCEEDED
 * - A2G_DECISION_PENDING_APPROVAL → [Escalate]
 * - A2G_DECISION_ERROR         → throws [A2gInternalErrorException]
 */
sealed class Verdict {

    /**
     * The action is authorized. The receipt string is a JSON-serialized
     * [GatewayReceipt] that must be presented to the Enforcing Gateway
     * via [GatewayClient.enforce] before any bus write is performed (SPEC §9.3).
     *
     * An ALLOW verdict does NOT by itself authorize the action — only a
     * successful gateway verification does (SPEC §1.4 invariant 3).
     */
    data class Allow(
        /** JSON-serialized GatewayReceipt for the Enforcing Gateway. */
        val receipt: String,
        /** UUID from the a2g-core Verdict; useful for audit correlation. */
        val verdictId: String,
        /** The policy rule that produced ALLOW (informational). */
        val policyRule: String,
    ) : Verdict()

    /**
     * The action is not permitted. DENY is terminal: the action MUST NOT proceed.
     *
     * Also used for EXPIRED (reasonCode = MANDATE_TTL_EXCEEDED) since both are
     * terminal for enforcement purposes (SPEC §2.1).
     */
    data class Deny(
        /** Machine-readable reason code for programmatic handling. */
        val reasonCode: ReasonCode,
        /**
         * Human-readable policy rule string from the decision engine.
         * Suitable for display in assistant speech or developer logs.
         * OEM localisation: map [reasonCode] to strings.xml for UI display.
         */
        val humanText: String,
        /** UUID from the a2g-core Verdict; useful for audit correlation. */
        val verdictId: String,
    ) : Verdict()

    /**
     * The action requires human-in-the-loop approval before it may proceed
     * (SPEC §2.1 PENDING_APPROVAL). The action MUST NOT proceed based on this
     * verdict alone.
     *
     * Workflow (ADR-0015 binding key custody):
     * 1. Present [unsignedBindingJson] to the gateway's SignBinding endpoint
     *    via [GatewayClient.signBinding].
     * 2. Await operator approval (gateway's SubmitGrant flow).
     * 3. Call [A2g.decideWithApproval] with the signed binding + approval grant.
     */
    data class Escalate(
        /**
         * Unsigned PendingApprovalBinding JSON. Present this to the gateway's
         * SignBinding operation — the gateway signs it with its binding key
         * (ADR-0015) and returns the signed blob.
         */
        val unsignedBindingJson: String,
        /** UUID binding_id for correlation across the HITL flow. */
        val bindingId: String,
        /** SHA-256 request hash binding this escalation to the exact action. */
        val requestHash: String,
    ) : Verdict()
}

/**
 * Machine-readable reason codes for [Verdict.Deny].
 *
 * These mirror the policy_rule prefix strings produced by a2g-core's decision
 * pipeline. The [ReasonCodeSyncTest] asserts that no Rust policy_rule prefix
 * is unmapped here, so Kotlin callers can switch exhaustively without fallthrough.
 *
 * OEM localisation: map each ReasonCode to a user-facing string in strings.xml
 * (see res/values/strings.xml for the default English map). The contract is
 * documented in the SDK README under "Localisation for OEMs".
 *
 * ADR-0021: the sync test in ReasonCodeSyncTest.kt asserts that every known
 * policy_rule prefix from a2g-core maps to exactly one ReasonCode. If a new
 * policy_rule is added to Rust, the test fails until this enum is updated.
 */
enum class ReasonCode {
    /** Mandate signature failed verification (Step 1). */
    MANDATE_INVALID,

    /** Mandate TTL has elapsed; also covers A2G_DECISION_EXPIRED (Step 2). */
    MANDATE_TTL_EXCEEDED,

    /** Tool not in mandate's capabilities.tools list (Step 3). */
    TOOL_NOT_AUTHORIZED,

    /** Request parameters violate filesystem/network/command boundary (Step 4). */
    BOUNDARY_VIOLATION,

    /** Sensitive tool denied because vehicle state gate was not satisfied (Step 4.5). */
    VEHICLE_STATE_VIOLATION,

    /** Tool is in the vehicle Forbidden domain — unconditional deny (Pre-check). */
    VEHICLE_FORBIDDEN_DOMAIN,

    /**
     * Tool is in the cockpit Forbidden domain (pii.profile.export) —
     * unconditional deny (ADR-0018, Pre-check Step 1.5).
     */
    COCKPIT_FORBIDDEN_DOMAIN,

    /** Current time is outside the mandate's operating_hours window (Step 5). */
    JURISDICTION_VIOLATION,

    /** Call volume exceeded max_calls_per_minute (Step 7). */
    RATE_LIMIT_EXCEEDED,

    /** Mandate has been revoked in the ledger (Step 0). */
    MANDATE_REVOKED,

    /** Mandate issuer not in the trust anchor's accepted roots (Step 1.5, ADR-0014). */
    ISSUER_UNTRUSTED,

    /**
     * Empty tool name or other structurally invalid request (Pre-check: empty
     * capability identifier, SPEC §5.2).
     */
    INVALID_REQUEST,

    /**
     * Tool requires the pii.grant sentinel in the mandate's tools list but it
     * is absent (Step 3.5, ADR-0018).
     */
    PII_GRANT_REQUIRED,

    /**
     * Internal error in the a2g-ffi layer (panic, encoding failure, etc.).
     * Corresponds to A2G_DECISION_ERROR.
     */
    INTERNAL_ERROR,

    /**
     * Unrecognised policy_rule prefix. This value indicates the Kotlin SDK is
     * out of sync with the Rust core — update [ReasonCode] and the sync test.
     */
    UNKNOWN;

    companion object {
        /**
         * Parse a policy_rule string from a2g-core into a [ReasonCode].
         *
         * The policy_rule may contain additional detail after the prefix
         * (e.g. "tool_not_authorized: 'foo' not in capabilities.tools").
         * This function matches on the prefix only.
         */
        fun fromPolicyRule(policyRule: String): ReasonCode = when {
            policyRule.startsWith("mandate_invalid") -> MANDATE_INVALID
            policyRule.startsWith("mandate_ttl_exceeded") -> MANDATE_TTL_EXCEEDED
            policyRule.startsWith("mandate_revoked") -> MANDATE_REVOKED
            policyRule.startsWith("tool_not_authorized") -> TOOL_NOT_AUTHORIZED
            policyRule.startsWith("boundary_violation") -> BOUNDARY_VIOLATION
            policyRule.startsWith("vehicle_state_violation") -> VEHICLE_STATE_VIOLATION
            policyRule.startsWith("vehicle_forbidden_domain") -> VEHICLE_FORBIDDEN_DOMAIN
            policyRule.startsWith("cockpit_forbidden_domain") -> COCKPIT_FORBIDDEN_DOMAIN
            policyRule.startsWith("jurisdiction_violation") -> JURISDICTION_VIOLATION
            policyRule.startsWith("rate_limit_exceeded") -> RATE_LIMIT_EXCEEDED
            policyRule.startsWith("issuer_untrusted") -> ISSUER_UNTRUSTED
            policyRule.startsWith("invalid_request") -> INVALID_REQUEST
            policyRule.startsWith("pii_grant_required") -> PII_GRANT_REQUIRED
            policyRule.startsWith("ffi_error") -> INTERNAL_ERROR
            else -> UNKNOWN
        }
    }
}
