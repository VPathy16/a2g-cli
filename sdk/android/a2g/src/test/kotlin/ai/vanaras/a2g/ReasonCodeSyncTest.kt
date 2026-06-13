package ai.vanaras.a2g

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Asserts that every known a2g-core policy_rule prefix maps to a non-UNKNOWN
 * ReasonCode in the Kotlin SDK.
 *
 * ADR-0021 requirement: this test prevents ReasonCode from drifting out of
 * sync with the Rust policy_rule strings. If a new policy_rule is added to
 * a2g-core (in crates/a2g-core/src/enforce.rs or the classifier), this test
 * will fail until [ReasonCode] and [ReasonCode.fromPolicyRule] are updated.
 *
 * The exhaustive list below is derived from a2g-core's decision pipeline:
 * - enforce.rs: forbidden domain pre-checks
 * - cockpit.rs: cockpit domain checks
 * - mandate.rs: Steps 0-7 policy_rule strings
 */
class ReasonCodeSyncTest {

    /**
     * Complete list of all policy_rule prefix strings produced by a2g-core.
     *
     * Any addition to this list requires a matching [ReasonCode] entry and
     * a case in [ReasonCode.fromPolicyRule] — the test enforces this.
     *
     * Source: grep for `policy_rule` assignments in:
     *   crates/a2g-core/src/enforce.rs
     *   crates/a2g-core/src/cockpit.rs
     *   crates/a2g-ffi/src/lib.rs (ffi_error)
     */
    private val knownPolicyRulePrefixes = listOf(
        // Pre-checks
        "invalid_request",
        "vehicle_forbidden_domain",
        "cockpit_forbidden_domain",
        // Step 0
        "mandate_revoked",
        // Step 1
        "mandate_invalid",
        // Step 2
        "mandate_ttl_exceeded",
        // Step 3
        "tool_not_authorized",
        // Step 3.5 (ADR-0018 pii.grant gate)
        "pii_grant_required",
        // Step 4
        "boundary_violation",
        // Step 4.5
        "vehicle_state_violation",
        // Step 5
        "jurisdiction_violation",
        // Step 7
        "rate_limit_exceeded",
        // Step 1.5 (ADR-0014)
        "issuer_untrusted",
        // FFI layer
        "ffi_error",
    )

    @Test
    fun `all known policy_rule prefixes map to non-UNKNOWN ReasonCode`() {
        val unmapped = knownPolicyRulePrefixes.filter { prefix ->
            ReasonCode.fromPolicyRule(prefix) == ReasonCode.UNKNOWN
        }
        assert(unmapped.isEmpty()) {
            "The following policy_rule prefixes are not mapped in ReasonCode.fromPolicyRule():\n" +
                unmapped.joinToString("\n  - ", "  - ") +
                "\n\nAdd a case in ReasonCode.fromPolicyRule() and a matching enum constant."
        }
    }

    @Test
    fun `all known policy_rule prefixes return a specific ReasonCode`() {
        for (prefix in knownPolicyRulePrefixes) {
            val code = ReasonCode.fromPolicyRule(prefix)
            assertNotEquals(
                "policy_rule prefix '$prefix' should not map to UNKNOWN",
                ReasonCode.UNKNOWN,
                code,
            )
            assertNotNull("ReasonCode must not be null for prefix '$prefix'", code)
        }
    }

    @Test
    fun `fromPolicyRule handles policy_rule with detail suffix`() {
        // Rust policy_rule strings often carry detail after the prefix
        val detailedRules = mapOf(
            "tool_not_authorized: 'foo' not in capabilities.tools" to ReasonCode.TOOL_NOT_AUTHORIZED,
            "mandate_invalid: signature verification failed" to ReasonCode.MANDATE_INVALID,
            "vehicle_forbidden_domain: 'CRUISE_CONTROL_COMMAND' is safety-critical" to ReasonCode.VEHICLE_FORBIDDEN_DOMAIN,
            "boundary_violation: path '/etc/passwd' matches fs_deny" to ReasonCode.BOUNDARY_VIOLATION,
            "jurisdiction_violation: outside 09:00-17:00" to ReasonCode.JURISDICTION_VIOLATION,
        )
        for ((rule, expected) in detailedRules) {
            val actual = ReasonCode.fromPolicyRule(rule)
            assertEquals(
                "policy_rule '$rule' should map to $expected, got $actual",
                expected,
                actual,
            )
        }
    }

    @Test
    fun `UNKNOWN is returned only for truly unrecognized prefixes`() {
        val code = ReasonCode.fromPolicyRule("completely_unknown_rule_xyz_123")
        assertEquals(ReasonCode.UNKNOWN, code)
    }

    @Test
    fun `ReasonCode has no duplicate enum names`() {
        val names = ReasonCode.values().map { it.name }
        val distinct = names.distinct()
        assertEquals(
            "ReasonCode enum has duplicate names: ${names.groupBy { it }.filter { it.value.size > 1 }.keys}",
            names.size,
            distinct.size,
        )
    }
}
