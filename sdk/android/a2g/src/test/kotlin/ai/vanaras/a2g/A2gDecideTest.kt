package ai.vanaras.a2g

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Host-JVM unit tests for A2g.decide() using MockJniBridge.
 *
 * These tests run on the JVM without an Android device or the a2g-ffi
 * shared library. MockJniBridge faithfully simulates the real behavior.
 *
 * ADR-0021 requirements verified:
 * - DENY on vehicle forbidden domain tools (Forbidden pre-check).
 * - DENY on pii.profile.export (cockpit Forbidden, ADR-0018).
 * - pii.grant reserved-name throws PiiGrantReservedNameException (SPEC §3.6.3).
 * - DENY on tool not in mandate.
 * - ESCALATE on always-HITL cockpit tools.
 * - ADR-0015: null/wrong-length bindingPubkey throws A2gNullPubkeyException.
 * - A2gNotInitializedException before init.
 */
class A2gDecideTest {

    // Dummy mandate bytes — mock bridge ignores content
    private val fakeMandateCbor = ByteArray(32) { 0x42 }

    @Before
    fun setUp() {
        A2g.setBridgeForTesting(MockJniBridge())
        A2g.init(fakeMandateCbor, TrustAnchor.SelfSovereign)
    }

    @After
    fun tearDown() {
        A2g.resetForTesting()
        A2g.resetBridge()
    }

    // ── Allowed tools ──────────────────────────────────────────────────────────

    @Test
    fun `decide - allowed comfort tool returns Allow`() {
        val verdict = A2g.decide("read_file", "{}")
        assertTrue("Expected Allow, got $verdict", verdict is Verdict.Allow)
    }

    @Test
    fun `decide - climate tool returns Allow`() {
        val verdict = A2g.decide("vehicle.climate.set_temperature", """{"temp_c": 22}""")
        assertTrue("Expected Allow, got $verdict", verdict is Verdict.Allow)
    }

    // ── Vehicle Forbidden domain (SPEC §5.3) ───────────────────────────────────

    @Test
    fun `decide - CRUISE_CONTROL_COMMAND returns Deny vehicle_forbidden_domain`() {
        val verdict = A2g.decide("CRUISE_CONTROL_COMMAND", "{}")
        assertTrue("Expected Deny, got $verdict", verdict is Verdict.Deny)
        val deny = verdict as Verdict.Deny
        assertEquals(ReasonCode.VEHICLE_FORBIDDEN_DOMAIN, deny.reasonCode)
    }

    @Test
    fun `decide - BRAKE_command returns Deny vehicle_forbidden_domain`() {
        val verdict = A2g.decide("BRAKE_FORCE_REQUEST", "{}")
        assertTrue("Expected Deny, got $verdict", verdict is Verdict.Deny)
        assertEquals(ReasonCode.VEHICLE_FORBIDDEN_DOMAIN, (verdict as Verdict.Deny).reasonCode)
    }

    @Test
    fun `decide - ADAS tool returns Deny vehicle_forbidden_domain`() {
        val verdict = A2g.decide("ADAS_LANE_KEEP_ASSIST", "{}")
        assertTrue("Expected Deny, got $verdict", verdict is Verdict.Deny)
        assertEquals(ReasonCode.VEHICLE_FORBIDDEN_DOMAIN, (verdict as Verdict.Deny).reasonCode)
    }

    // ── Cockpit Forbidden domain (ADR-0018) ────────────────────────────────────

    @Test
    fun `decide - pii_profile_export returns Deny cockpit_forbidden_domain`() {
        val verdict = A2g.decide("pii.profile.export", "{}")
        assertTrue("Expected Deny, got $verdict", verdict is Verdict.Deny)
        val deny = verdict as Verdict.Deny
        assertEquals(ReasonCode.COCKPIT_FORBIDDEN_DOMAIN, deny.reasonCode)
    }

    // ── pii.grant reserved name (SPEC §3.6.3) — must throw, never Allow ─────

    @Test(expected = PiiGrantReservedNameException::class)
    fun `decide - pii_grant throws PiiGrantReservedNameException`() {
        // SPEC §3.6.3: "pii.grant" is a reserved sentinel, not a callable tool.
        // An attempt to invoke it MUST be refused structurally — never return Allow.
        A2g.decide("pii.grant", "{}")
    }

    @Test
    fun `decide - pii_grant never returns Allow`() {
        // Additional assertion: even if someone catches the exception, the
        // result is never Allow.
        var verdict: Verdict? = null
        try {
            verdict = A2g.decide("pii.grant", "{}")
        } catch (e: PiiGrantReservedNameException) {
            // Expected — test passes
            return
        }
        // If no exception was thrown, the result must not be Allow
        assertTrue(
            "pii.grant must never return Allow (SPEC §3.6.3), got: $verdict",
            verdict !is Verdict.Allow
        )
    }

    // ── Tool not authorized ────────────────────────────────────────────────────

    @Test
    fun `decide - tool not in mandate returns Deny tool_not_authorized`() {
        val verdict = A2g.decide("unknown_tool_xyz", "{}")
        assertTrue("Expected Deny, got $verdict", verdict is Verdict.Deny)
        assertEquals(ReasonCode.TOOL_NOT_AUTHORIZED, (verdict as Verdict.Deny).reasonCode)
    }

    // ── Always-HITL cockpit tools (ADR-0018) ──────────────────────────────────

    @Test
    fun `decide - comms_call_place returns Escalate (always-HITL)`() {
        // comms.call.place is always-HITL even when in allowed tools (ADR-0018)
        val bridge = MockJniBridge(
            allowedTools = MockJniBridge.DEFAULT_ALLOWED_TOOLS + "comms.call.place",
            escalateTools = emptySet(), // escalate_tools doesn't affect always-HITL
        )
        A2g.setBridgeForTesting(bridge)
        val verdict = A2g.decide("comms.call.place", "{}")
        assertTrue("Expected Escalate, got $verdict", verdict is Verdict.Escalate)
    }

    @Test
    fun `decide - pay_tool returns Escalate (always-HITL)`() {
        val bridge = MockJniBridge(
            allowedTools = MockJniBridge.DEFAULT_ALLOWED_TOOLS + "pay.card.charge",
        )
        A2g.setBridgeForTesting(bridge)
        val verdict = A2g.decide("pay.card.charge", "{}")
        assertTrue("Expected Escalate (pay.* always-HITL), got $verdict", verdict is Verdict.Escalate)
    }

    // ── Not initialized ────────────────────────────────────────────────────────

    @Test(expected = A2gNotInitializedException::class)
    fun `decide before init throws A2gNotInitializedException`() {
        A2g.resetForTesting()
        A2g.decide("read_file", "{}")
    }

    // ── Phase 2: ADR-0015 null pubkey fail-explicit ───────────────────────────

    @Test(expected = A2gNullPubkeyException::class)
    fun `decideWithApproval - wrong-length pubkey throws A2gNullPubkeyException`() {
        // ADR-0015: NULL pubkey must surface as exception, never default to Allow
        A2g.decideWithApproval(
            tool = "vehicle.door.unlock",
            paramsJson = "{}",
            signedBindingJson = """{"binding_id":"test","a2g_mac":"deadbeef"}""",
            bindingPubkey = ByteArray(16), // Wrong length — should throw
            grantJson = "{}",
        )
    }

    @Test(expected = A2gNullPubkeyException::class)
    fun `decideWithApproval - empty pubkey throws A2gNullPubkeyException`() {
        A2g.decideWithApproval(
            tool = "vehicle.door.unlock",
            paramsJson = "{}",
            signedBindingJson = "{}",
            bindingPubkey = ByteArray(0), // Empty — should throw
            grantJson = "{}",
        )
    }

    @Test
    fun `decideWithApproval - valid 32-byte pubkey does not throw`() {
        val verdict = A2g.decideWithApproval(
            tool = "vehicle.door.unlock",
            paramsJson = "{}",
            signedBindingJson = """{"binding_id":"test","a2g_mac":"cafebabe"}""",
            bindingPubkey = ByteArray(32) { 0x01 }, // Correct length
            grantJson = """{"approver_did":"did:a2g:test"}""",
        )
        // Mock allows this — just check no exception is thrown and result is not an error
        assertTrue("Expected Allow or Deny, not an exception", verdict is Verdict.Allow || verdict is Verdict.Deny)
    }

    @Test(expected = PiiGrantReservedNameException::class)
    fun `decideWithApproval - pii_grant throws PiiGrantReservedNameException`() {
        // Even in Phase 2, pii.grant must not be callable (SPEC §3.6.3)
        A2g.decideWithApproval(
            tool = "pii.grant",
            paramsJson = "{}",
            signedBindingJson = "{}",
            bindingPubkey = ByteArray(32),
            grantJson = "{}",
        )
    }
}
