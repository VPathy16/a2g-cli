package ai.vanaras.a2g.sample

import ai.vanaras.a2g.A2g
import ai.vanaras.a2g.GatewayClient
import ai.vanaras.a2g.ReasonCode
import ai.vanaras.a2g.TrustAnchor
import ai.vanaras.a2g.UnixSocketTransport
import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView

/**
 * DemoActivity — A2G governance demonstration for AAOS app developers.
 *
 * Shows three governed vehicle actions and one cockpit action:
 *
 * 1. Climate (ALLOW)     — vehicle.climate.set_temperature: Comfort tier.
 *                          Expected: green "ALLOW" badge on a valid mandate.
 *
 * 2. Window at speed (DENY) — vehicle.window.set_position: Sensitive tier.
 *                             Expected: red "DENY" with state_violation speech
 *                             when vehicle is moving (speed ≥ 5 km/h).
 *
 * 3. Cruise control (STRUCTURAL REFUSED) — CRUISE_CONTROL_COMMAND: Forbidden tier.
 *                             Expected: dark red "REFUSED" badge, never ALLOW.
 *
 * 4. Send SMS (ESCALATE) — comms.sms.send: Cockpit always-HITL.
 *                          Expected: amber "ESCALATE" badge with binding_id.
 *
 * Quick start: see sdk/android/README.md §"Running the demo".
 */
class DemoActivity : Activity() {

    companion object {
        private const val TAG = "A2gDemoActivity"

        /**
         * Gateway socket path — change to match your gateway launch arguments.
         * Default from a2g-gateway --socket /tmp/a2g_demo.sock
         */
        private const val GATEWAY_SOCKET = "/tmp/a2g_demo.sock"

        /**
         * Mandate CBOR file — copy from your governance toolchain.
         * For the demo, the gateway prints the mandate path on startup.
         *
         * In a real AAOS deployment, mandates are provisioned via the OEM's
         * policy distribution system and stored in the Keystore.
         */
        private const val MANDATE_ASSET = "demo_mandate.cbor"
    }

    private lateinit var client: GovernedCarClient
    private lateinit var statusText: TextView

    // Buttons
    private lateinit var climateButton: Button
    private lateinit var windowButton: Button
    private lateinit var cruiseButton: Button
    private lateinit var smsButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_demo)

        statusText = findViewById(R.id.status_text)
        climateButton = findViewById(R.id.btn_climate)
        windowButton = findViewById(R.id.btn_window)
        cruiseButton = findViewById(R.id.btn_cruise)
        smsButton = findViewById(R.id.btn_sms)

        initA2g()
        setupButtons()
    }

    override fun onStart() {
        super.onStart()
        client.connect()
    }

    override fun onStop() {
        super.onStop()
        client.disconnect()
    }

    // ── Initialization ─────────────────────────────────────────────────────────

    private fun initA2g() {
        // Load mandate CBOR from assets
        val mandateCbor = try {
            assets.open(MANDATE_ASSET).readBytes()
        } catch (e: Exception) {
            Log.w(TAG, "Could not load $MANDATE_ASSET: ${e.message}. Using empty mandate.")
            ByteArray(0)
        }

        // Initialize A2G with self-sovereign trust (demo mode).
        // Production: use TrustAnchor.Roots(listOf(gatewayPublicKey))
        A2g.init(mandateCbor, TrustAnchor.SelfSovereign)

        val gatewayTransport = UnixSocketTransport(GATEWAY_SOCKET)
        val gatewayClient = GatewayClient(gatewayTransport)

        client = GovernedCarClient(this, gatewayClient)
    }

    // ── Button handlers ────────────────────────────────────────────────────────

    private fun setupButtons() {
        // Button 1: Climate — Comfort tier, expect ALLOW
        climateButton.setOnClickListener {
            showStatus("Requesting climate set_temperature…")
            client.setHvacTemperature(22.0f) { result ->
                runOnUiThread { handleResult("CLIMATE", result) }
            }
        }

        // Button 2: Window — Sensitive tier, expect DENY if vehicle moving
        windowButton.setOnClickListener {
            showStatus("Requesting window position change…")
            client.setWindowPosition(areaId = 1, position = 50) { result ->
                runOnUiThread { handleResult("WINDOW", result) }
            }
        }

        // Button 3: Cruise control — Forbidden tier, structurally REFUSED
        cruiseButton.setOnClickListener {
            showStatus("Requesting cruise control (Forbidden domain)…")
            // CRUISE_CONTROL_COMMAND is in the Forbidden domain.
            // This calls A2g.decide directly to show the REFUSED path.
            runOnUiThread {
                try {
                    val verdict = A2g.decide("CRUISE_CONTROL_COMMAND", "{}")
                    handleVerdictDirect("CRUISE", verdict)
                } catch (e: Exception) {
                    showStatus("CRUISE: Exception: ${e.message}", badgeColor = STATUS_RED)
                }
            }
        }

        // Button 4: Send SMS — cockpit always-HITL, expect ESCALATE
        smsButton.setOnClickListener {
            showStatus("Requesting SMS send (always-HITL)…")
            client.sendSms(
                recipient = "+1-555-DEMO",
                messageText = "Hello from the A2G demo!"
            ) { result ->
                runOnUiThread { handleResult("SMS", result) }
            }
        }
    }

    // ── Result display ─────────────────────────────────────────────────────────

    private fun handleResult(action: String, result: ActionResult) {
        when (result) {
            is ActionResult.Allowed -> {
                val msg = "$action: ALLOW ✓\nVerdictId: ${result.verdictId}"
                showStatus(msg, badgeColor = STATUS_GREEN)
                Log.i(TAG, msg)
            }
            is ActionResult.Denied -> {
                val reasonStr = reasonToString(result.reasonCode)
                val msg = "$action: DENY ✗\n$reasonStr\n\n${result.humanText}"
                val color = if (result.reasonCode == ReasonCode.VEHICLE_FORBIDDEN_DOMAIN ||
                    result.reasonCode == ReasonCode.COCKPIT_FORBIDDEN_DOMAIN) {
                    STATUS_DARK_RED  // Structural refusal
                } else {
                    STATUS_RED       // Policy denial
                }
                showStatus(msg, badgeColor = color)
                Log.i(TAG, "$action DENIED: ${result.humanText}")
            }
            is ActionResult.Escalated -> {
                val msg = "$action: ESCALATE ⏳\nBinding: ${result.bindingId}\n" +
                    "Awaiting operator approval"
                showStatus(msg, badgeColor = STATUS_AMBER)
                Log.i(TAG, "$action ESCALATED: bindingId=${result.bindingId}")
            }
        }
    }

    private fun handleVerdictDirect(action: String, verdict: ai.vanaras.a2g.Verdict) {
        when (verdict) {
            is ai.vanaras.a2g.Verdict.Allow ->
                showStatus("$action: ALLOW ✓", badgeColor = STATUS_GREEN)
            is ai.vanaras.a2g.Verdict.Deny -> {
                val isStructural = verdict.reasonCode == ReasonCode.VEHICLE_FORBIDDEN_DOMAIN ||
                    verdict.reasonCode == ReasonCode.COCKPIT_FORBIDDEN_DOMAIN
                val badge = if (isStructural) "STRUCTURALLY REFUSED" else "DENY"
                val color = if (isStructural) STATUS_DARK_RED else STATUS_RED
                showStatus("$action: $badge ✗\n${verdict.humanText}", badgeColor = color)
            }
            is ai.vanaras.a2g.Verdict.Escalate ->
                showStatus("$action: ESCALATE ⏳\n${verdict.bindingId}", badgeColor = STATUS_AMBER)
        }
    }

    private fun showStatus(
        text: String,
        badgeColor: Int = STATUS_NEUTRAL,
    ) {
        statusText.text = text
        statusText.setBackgroundColor(badgeColor)
    }

    private fun reasonToString(code: ReasonCode): String {
        val resId = reasonCodeToStringRes(code)
        return try { getString(resId) } catch (_: Exception) { code.name }
    }

    // ── Color constants ────────────────────────────────────────────────────────

    companion object {
        private const val STATUS_GREEN    = 0xFF4CAF50.toInt()  // Material Green 500
        private const val STATUS_RED      = 0xFFF44336.toInt()  // Material Red 500
        private const val STATUS_DARK_RED = 0xFFB71C1C.toInt()  // Material Red 900
        private const val STATUS_AMBER    = 0xFFFFC107.toInt()  // Material Amber 500
        private const val STATUS_NEUTRAL  = 0xFF9E9E9E.toInt()  // Material Grey 500
    }
}

/**
 * Map a [ReasonCode] to the corresponding string resource ID.
 *
 * OEM localisation: override these strings in res/values-<locale>/strings.xml.
 * The resource names are the A2G SDK contract; do not rename them.
 */
fun reasonCodeToStringRes(code: ReasonCode): Int = when (code) {
    ReasonCode.MANDATE_INVALID      -> R.string.a2g_reason_mandate_invalid
    ReasonCode.MANDATE_TTL_EXCEEDED -> R.string.a2g_reason_mandate_ttl_exceeded
    ReasonCode.TOOL_NOT_AUTHORIZED  -> R.string.a2g_reason_tool_not_authorized
    ReasonCode.BOUNDARY_VIOLATION   -> R.string.a2g_reason_boundary_violation
    ReasonCode.VEHICLE_STATE_VIOLATION -> R.string.a2g_reason_vehicle_state_violation
    ReasonCode.VEHICLE_FORBIDDEN_DOMAIN -> R.string.a2g_reason_vehicle_forbidden_domain
    ReasonCode.COCKPIT_FORBIDDEN_DOMAIN -> R.string.a2g_reason_cockpit_forbidden_domain
    ReasonCode.JURISDICTION_VIOLATION -> R.string.a2g_reason_jurisdiction_violation
    ReasonCode.RATE_LIMIT_EXCEEDED  -> R.string.a2g_reason_rate_limit_exceeded
    ReasonCode.MANDATE_REVOKED      -> R.string.a2g_reason_mandate_revoked
    ReasonCode.ISSUER_UNTRUSTED     -> R.string.a2g_reason_issuer_untrusted
    ReasonCode.INVALID_REQUEST      -> R.string.a2g_reason_invalid_request
    ReasonCode.PII_GRANT_REQUIRED   -> R.string.a2g_reason_pii_grant_required
    ReasonCode.INTERNAL_ERROR       -> R.string.a2g_reason_internal_error
    ReasonCode.UNKNOWN              -> R.string.a2g_reason_unknown
}
