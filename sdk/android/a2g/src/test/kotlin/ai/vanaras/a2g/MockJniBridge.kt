package ai.vanaras.a2g

/**
 * Mock JNI bridge for host-JVM unit tests.
 *
 * This mock simulates the real a2g-ffi behavior WITHOUT the native library.
 * Tests run on any JVM (no Android device, no cargo-ndk).
 *
 * CRITICAL INVARIANTS — these must match the real native behavior exactly:
 *
 * 1. DENY on forbidden vehicle tools (propulsion, braking, steering, ADAS).
 * 2. DENY on cockpit forbidden tools (pii.profile.export).
 * 3. DENY on pii.grant invoked as a callable tool (SPEC §3.6.3 reserved name).
 *    Note: the A2g.decide() layer already throws before reaching here;
 *    this mock also denies for defense-in-depth.
 * 4. DENY on tools not in the mandate's allowed list.
 * 5. ESCALATE on always-HITL cockpit tools (pay.*, comms.call.place, etc.).
 * 6. NULL-pubkey → A2gNullPubkeyException (fail-explicit, ADR-0015).
 * 7. NEVER silently default to ALLOW for unknown inputs.
 *
 * The mock does NOT verify mandate signatures — it uses a simple allow-list.
 * Configure [allowedTools] and [escalateTools] when constructing.
 */
class MockJniBridge(
    /**
     * Tools that are authorized (would be in mandate.capabilities.tools).
     * Defaults to a set of common Comfort/Sensitive tools for demo purposes.
     */
    private val allowedTools: Set<String> = DEFAULT_ALLOWED_TOOLS,

    /**
     * Tools that trigger HITL escalation even when in allowedTools.
     * Always includes the always-HITL cockpit namespaces.
     */
    private val escalateTools: Set<String> = ALWAYS_HITL_TOOLS,
) : JniBridge {

    companion object {

        /** Default allowed tools for tests — mirrors the FFI smoke-test mandate. */
        val DEFAULT_ALLOWED_TOOLS: Set<String> = setOf(
            "read_file",
            "write_file",
            "vehicle.climate.set_temperature",
            "vehicle.seat.adjust",
            "vehicle.window.set_position",
            "vehicle.door.unlock",
            "comms.contacts.read",  // pii-gated; needs pii.grant in mandate
        )

        /**
         * Tools that are always-HITL regardless of mandate contents (ADR-0018).
         * Maps to cockpit domains: pay.*, comms.call.place, comms.sms.send, etc.
         */
        val ALWAYS_HITL_TOOLS: Set<String> = setOf(
            "comms.call.place",
            "comms.sms.send",
        )

        /**
         * Vehicle forbidden domain prefixes — structural deny, no mandate override.
         * Matches a2g-core's classifier for the Forbidden tier.
         */
        private val VEHICLE_FORBIDDEN_PREFIXES: List<String> = listOf(
            "PROPULSION_",
            "BRAKE_",
            "STEERING_",
            "ADAS_",
            "CRUISE_CONTROL_COMMAND",
            "ENGINE_",
        )

        /**
         * Cockpit forbidden tools (ADR-0018 §3.6.1).
         * pii.profile.export is structurally Forbidden.
         */
        private val COCKPIT_FORBIDDEN: Set<String> = setOf(
            "pii.profile.export",
        )

        /**
         * Always-HITL cockpit namespace prefixes.
         * Unknown sub-operations within these namespaces are fail-closed HITL.
         */
        private val COCKPIT_HITL_PREFIXES: List<String> = listOf(
            "pay.",
            "comms.",
        )

        /** Dummy verdictId for mock responses. */
        private const val MOCK_VERDICT_ID = "mock-verdict-00000000-0000-0000-0000-000000000000"
        private const val MOCK_BINDING_ID = "mock-binding-00000000-0000-0000-0000-000000000000"
        private val MOCK_REQUEST_HASH = "a".repeat(64)
        private const val MOCK_RECEIPT = "{\"mock\":true,\"verdict_id\":\"$MOCK_VERDICT_ID\"}"
    }

    override fun decide(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
    ): Verdict {
        // Pre-check 1: empty tool name
        if (tool.isEmpty()) {
            return Verdict.Deny(
                reasonCode = ReasonCode.INVALID_REQUEST,
                humanText = "invalid_request: tool name must not be empty",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // Pre-check 2: pii.grant reserved name (defense-in-depth; A2g.decide() also checks)
        if (tool == "pii.grant") {
            return Verdict.Deny(
                reasonCode = ReasonCode.TOOL_NOT_AUTHORIZED,
                humanText = "tool_not_authorized: 'pii.grant' is a reserved sentinel",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // Pre-check 3: vehicle forbidden domain (SPEC §5.3, fires before mandate eval)
        if (isVehicleForbidden(tool)) {
            return Verdict.Deny(
                reasonCode = ReasonCode.VEHICLE_FORBIDDEN_DOMAIN,
                humanText = "vehicle_forbidden_domain: '$tool' is in the safety-critical domain",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // Pre-check 4: cockpit forbidden domain (ADR-0018 §3.6.1, fires before mandate eval)
        if (COCKPIT_FORBIDDEN.contains(tool)) {
            return Verdict.Deny(
                reasonCode = ReasonCode.COCKPIT_FORBIDDEN_DOMAIN,
                humanText = "cockpit_forbidden_domain: '$tool' is forbidden by ADR-0018",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // Step 3: tool authorization check
        if (!allowedTools.contains(tool)) {
            return Verdict.Deny(
                reasonCode = ReasonCode.TOOL_NOT_AUTHORIZED,
                humanText = "tool_not_authorized: '$tool' not in capabilities.tools",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // Step 6: always-HITL cockpit tools
        if (isCockpitAlwaysHitl(tool)) {
            return Verdict.Escalate(
                unsignedBindingJson = buildMockBinding(tool),
                bindingId = MOCK_BINDING_ID,
                requestHash = MOCK_REQUEST_HASH,
            )
        }

        // Step 6: explicit escalation tools
        if (escalateTools.contains(tool)) {
            return Verdict.Escalate(
                unsignedBindingJson = buildMockBinding(tool),
                bindingId = MOCK_BINDING_ID,
                requestHash = MOCK_REQUEST_HASH,
            )
        }

        // All checks pass: ALLOW
        return Verdict.Allow(
            receipt = MOCK_RECEIPT,
            verdictId = MOCK_VERDICT_ID,
            policyRule = "allow",
        )
    }

    override fun decideWithApproval(
        mandateCbor: ByteArray,
        trustAnchor: TrustAnchor,
        tool: String,
        paramsJson: String,
        signedBindingJson: String,
        bindingPubkey: ByteArray,
        grantJson: String,
    ): Verdict {
        // ADR-0015 fail-explicit: null/wrong-length pubkey → exception.
        // (The A2g.decideWithApproval() layer already checks; this is defense-in-depth.)
        if (bindingPubkey.size != 32) {
            throw A2gNullPubkeyException("MockJniBridge: expected 32 bytes, got ${bindingPubkey.size}")
        }

        // Phase 2 forbidden checks still apply (SPEC §5.15, §7.6)
        if (isVehicleForbidden(tool)) {
            return Verdict.Deny(
                reasonCode = ReasonCode.VEHICLE_FORBIDDEN_DOMAIN,
                humanText = "vehicle_forbidden_domain: '$tool' forbidden in Phase 2",
                verdictId = MOCK_VERDICT_ID,
            )
        }
        if (COCKPIT_FORBIDDEN.contains(tool)) {
            return Verdict.Deny(
                reasonCode = ReasonCode.COCKPIT_FORBIDDEN_DOMAIN,
                humanText = "cockpit_forbidden_domain: '$tool' forbidden in Phase 2",
                verdictId = MOCK_VERDICT_ID,
            )
        }

        // For the mock, if we have a signed binding and a grant, allow it.
        if (signedBindingJson.isNotEmpty() && grantJson.isNotEmpty()) {
            return Verdict.Allow(
                receipt = MOCK_RECEIPT,
                verdictId = MOCK_VERDICT_ID,
                policyRule = "allow (phase 2)",
            )
        }

        return Verdict.Deny(
            reasonCode = ReasonCode.MANDATE_INVALID,
            humanText = "mandate_invalid: missing binding or grant in Phase 2",
            verdictId = MOCK_VERDICT_ID,
        )
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun isVehicleForbidden(tool: String): Boolean =
        VEHICLE_FORBIDDEN_PREFIXES.any { tool.startsWith(it) }

    private fun isCockpitAlwaysHitl(tool: String): Boolean {
        // Specific always-HITL tools
        if (ALWAYS_HITL_TOOLS.contains(tool)) return true
        // Unknown sub-operations in cockpit namespaces are fail-closed HITL
        return COCKPIT_HITL_PREFIXES.any { prefix ->
            tool.startsWith(prefix) && !COCKPIT_FORBIDDEN.contains(tool)
        }
    }

    private fun buildMockBinding(tool: String): String =
        """{"binding_id":"$MOCK_BINDING_ID","request_hash":"$MOCK_REQUEST_HASH",""" +
            """"ttl_expires_at":"2099-01-01T00:00:00Z","tool":"$tool","escalate_to":""}"""
}
