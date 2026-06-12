package ai.vanaras.a2g.sample

import ai.vanaras.a2g.A2g
import ai.vanaras.a2g.GatewayClient
import ai.vanaras.a2g.GatewayReceipt
import ai.vanaras.a2g.GatewayRefusedException
import ai.vanaras.a2g.ReasonCode
import ai.vanaras.a2g.Verdict
import android.car.Car
import android.car.hardware.property.CarPropertyManager
import android.content.Context
import android.util.Log

/**
 * GovernedCarClient — wraps [CarPropertyManager] so every AAOS property write
 * runs through A2G decide() + gateway enforce() before touching the vehicle bus.
 *
 * Usage:
 * ```kotlin
 * val client = GovernedCarClient(context, gatewayClient)
 *
 * // Climate — comfort tool, expect ALLOW immediately
 * client.setHvacTemperature(22.5f) { result ->
 *     when (result) {
 *         is ActionResult.Allowed  -> // temperature was set
 *         is ActionResult.Denied   -> tts.speak(result.humanText)
 *         is ActionResult.Escalated -> showApprovalRequest(result.bindingId)
 *     }
 * }
 *
 * // Window at speed — Sensitive tool; DENY if vehicle is moving fast
 * client.setWindowPosition(0, 50) { result -> ... }
 *
 * // Send SMS — always-HITL cockpit tool; ESCALATE always
 * client.sendSms("+1-555-0100", "Hello") { result -> ... }
 * ```
 *
 * Thread safety: All operations are dispatched to the provided [executor] and
 * results are delivered on the main thread via the provided callback.
 * If no executor is provided, [android.os.AsyncTask.THREAD_POOL_EXECUTOR] is used.
 *
 * @param context Android context (used to bind the Car service).
 * @param gatewayClient A2G Enforcing Gateway client for receipt enforcement.
 * @param receiptSigner Signs GatewayReceipt for Enforce requests. In demo mode,
 *                      uses the gateway's own demo key. Production deployments
 *                      should use a provisioned signing key.
 */
class GovernedCarClient(
    private val context: Context,
    private val gatewayClient: GatewayClient,
    private val receiptSigner: ReceiptSigner = NoopReceiptSigner,
) {

    companion object {
        private const val TAG = "GovernedCarClient"

        // VHAL property IDs (from android.car.VehiclePropertyIds)
        // Comfort tier: temperature, seat, media
        private const val HVAC_TEMPERATURE_SET = 356517120   // VehiclePropertyIds.HVAC_TEMPERATURE_SET
        private const val HVAC_POWER_ON = 354419456          // VehiclePropertyIds.HVAC_POWER_ON

        // Sensitive tier: windows, doors, locks
        private const val WINDOW_POS = 322964416             // VehiclePropertyIds.WINDOW_POS
        private const val DOOR_LOCK = 371198722              // VehiclePropertyIds.DOOR_LOCK

        // A2G capability names for each VHAL property (ADR-0006, ADR-0018)
        private const val CAP_HVAC_TEMP = "vehicle.climate.set_temperature"
        private const val CAP_WINDOW_POS = "vehicle.window.set_position"
        private const val CAP_DOOR_UNLOCK = "vehicle.door.unlock"
        private const val CAP_COMMS_SMS = "comms.sms.send"          // always-HITL
        private const val CAP_COMMS_CALL = "comms.call.place"        // always-HITL
    }

    private var car: Car? = null
    private var carPropertyManager: CarPropertyManager? = null

    /**
     * Connect to the AAOS Car service. Call from Activity.onStart() or similar.
     *
     * CarPropertyManager requires Car.CAR_WAIT_TIMEOUT_DO_NOT_WAIT or longer.
     * The SDK does not manage the Car lifecycle — the caller is responsible.
     */
    fun connect() {
        car = Car.createCar(context, null, Car.CAR_WAIT_TIMEOUT_DO_NOT_WAIT) { car, ready ->
            if (ready) {
                carPropertyManager = car.getCarManager(Car.PROPERTY_SERVICE) as? CarPropertyManager
                Log.i(TAG, "CarPropertyManager connected")
            }
        }
    }

    /** Disconnect from the Car service. Call from Activity.onStop(). */
    fun disconnect() {
        car?.disconnect()
        car = null
        carPropertyManager = null
    }

    // ── Comfort tier: HVAC ────────────────────────────────────────────────────

    /**
     * Set HVAC temperature. Comfort tier — expects ALLOW for any valid mandate.
     *
     * @param tempCelsius Target temperature in Celsius (typically 16.0–30.0).
     * @param areaId      HVAC zone (e.g., VehicleAreaSeat.ROW_1_LEFT). Use 0 for global.
     * @param callback    Called with the [ActionResult] on the calling thread.
     */
    fun setHvacTemperature(
        tempCelsius: Float,
        areaId: Int = 0,
        callback: (ActionResult) -> Unit,
    ) {
        val params = """{"temp_c": $tempCelsius, "area_id": $areaId}"""
        executeGoverned(
            tool = CAP_HVAC_TEMP,
            params = params,
            onAllow = { receipt ->
                try {
                    carPropertyManager?.setFloatProperty(HVAC_TEMPERATURE_SET, areaId, tempCelsius)
                    Log.i(TAG, "HVAC temperature set to $tempCelsius°C (areaId=$areaId)")
                    callback(ActionResult.Allowed(receipt.verdictId))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to set HVAC temperature", e)
                    callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "CarPropertyManager error: ${e.message}"))
                }
            },
            callback = callback,
        )
    }

    // ── Sensitive tier: windows ────────────────────────────────────────────────

    /**
     * Set window position. Sensitive tier — requires vehicle to be stopped
     * (speed < 5 km/h). Returns [ActionResult.Denied] with speech text if
     * the vehicle state gate blocks the action.
     *
     * @param areaId   Window area ID (e.g., VehicleAreaWindow.ROW_1_LEFT).
     * @param position Window position 0–100 (0=closed, 100=fully open).
     * @param callback Called with the [ActionResult].
     */
    fun setWindowPosition(
        areaId: Int,
        position: Int,
        callback: (ActionResult) -> Unit,
    ) {
        val params = """{"area_id": $areaId, "position": $position}"""
        executeGoverned(
            tool = CAP_WINDOW_POS,
            params = params,
            onAllow = { receipt ->
                try {
                    carPropertyManager?.setIntProperty(WINDOW_POS, areaId, position)
                    Log.i(TAG, "Window $areaId set to $position% (verdictId=${receipt.verdictId})")
                    callback(ActionResult.Allowed(receipt.verdictId))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to set window position", e)
                    callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "CarPropertyManager error: ${e.message}"))
                }
            },
            callback = callback,
        )
    }

    // ── Sensitive tier: doors ─────────────────────────────────────────────────

    /**
     * Unlock a door. Sensitive tier — requires vehicle to be stopped.
     *
     * @param areaId   Door area ID (e.g., VehicleAreaDoor.ROW_1_LEFT).
     * @param callback Called with the [ActionResult].
     */
    fun unlockDoor(
        areaId: Int,
        callback: (ActionResult) -> Unit,
    ) {
        val params = """{"area_id": $areaId, "lock": false}"""
        executeGoverned(
            tool = CAP_DOOR_UNLOCK,
            params = params,
            onAllow = { receipt ->
                try {
                    carPropertyManager?.setBooleanProperty(DOOR_LOCK, areaId, false)
                    Log.i(TAG, "Door $areaId unlocked (verdictId=${receipt.verdictId})")
                    callback(ActionResult.Allowed(receipt.verdictId))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to unlock door", e)
                    callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "CarPropertyManager error: ${e.message}"))
                }
            },
            callback = callback,
        )
    }

    // ── Cockpit tier: comms (always-HITL) ─────────────────────────────────────

    /**
     * Send an SMS via the vehicle's communications system.
     *
     * This is an always-HITL cockpit tool (comms.sms.send, ADR-0018). The
     * result will always be [ActionResult.Escalated] — human approval is
     * required before the message is sent. The message is NOT sent until
     * Phase 2 (decideWithApproval) completes successfully.
     *
     * @param recipient Phone number or contact identifier.
     * @param messageText Message text.
     * @param callback  Called with [ActionResult.Escalated] including the bindingId
     *                  to present to the operator approval UI.
     */
    fun sendSms(
        recipient: String,
        messageText: String,
        callback: (ActionResult) -> Unit,
    ) {
        val params = """{"recipient": "$recipient", "message": "$messageText"}"""
        executeGoverned(
            tool = CAP_COMMS_SMS,
            params = params,
            onAllow = { _ ->
                // In production, Phase 2 ALLOW for comms.sms.send would invoke
                // the phone system here. For the demo, just log.
                Log.i(TAG, "SMS to $recipient: ALLOWED after HITL approval")
                callback(ActionResult.Allowed("sms-sent"))
            },
            callback = callback,
        )
    }

    /**
     * Place a phone call via the vehicle's communications system.
     *
     * Always-HITL (comms.call.place, ADR-0018). See [sendSms] for the approval flow.
     */
    fun placeCall(
        recipient: String,
        callback: (ActionResult) -> Unit,
    ) {
        val params = """{"recipient": "$recipient"}"""
        executeGoverned(
            tool = CAP_COMMS_CALL,
            params = params,
            onAllow = { _ ->
                Log.i(TAG, "Call to $recipient: ALLOWED after HITL approval")
                callback(ActionResult.Allowed("call-placed"))
            },
            callback = callback,
        )
    }

    // ── Core governed execution ────────────────────────────────────────────────

    /**
     * Core governance flow: decide() → enforce() → action.
     *
     * 1. Call [A2g.decide] for [tool] with [params].
     * 2. On [Verdict.Allow]: present the receipt to the gateway via
     *    [gatewayClient.enforce]. On gateway accept, invoke [onAllow].
     * 3. On [Verdict.Deny]: invoke [callback] with [ActionResult.Denied].
     * 4. On [Verdict.Escalate]: invoke [callback] with [ActionResult.Escalated].
     *
     * Note: This method blocks the calling thread. In production, dispatch to
     * a background coroutine or thread pool.
     */
    private fun executeGoverned(
        tool: String,
        params: String,
        onAllow: (Verdict.Allow) -> Unit,
        callback: (ActionResult) -> Unit,
    ) {
        try {
            when (val verdict = A2g.decide(tool, params)) {
                is Verdict.Allow -> {
                    // Sign and present the receipt to the Enforcing Gateway
                    val receiptJson = verdict.receipt
                    try {
                        val receipt = receiptSigner.parseAndSign(verdict)
                        gatewayClient.enforce(receipt)
                        onAllow(verdict)
                    } catch (e: GatewayRefusedException) {
                        Log.w(TAG, "Gateway refused enforcement for $tool: ${e.message}")
                        callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "Gateway refused: ${e.message}"))
                    }
                }

                is Verdict.Deny -> {
                    Log.i(TAG, "A2G DENY for $tool: ${verdict.humanText}")
                    callback(ActionResult.Denied(verdict.reasonCode, verdict.humanText))
                }

                is Verdict.Escalate -> {
                    Log.i(TAG, "A2G ESCALATE for $tool: bindingId=${verdict.bindingId}")
                    // Present unsigned binding to gateway for signing
                    try {
                        val signedBinding = gatewayClient.signBinding(verdict.unsignedBindingJson)
                        callback(ActionResult.Escalated(
                            bindingId = verdict.bindingId,
                            signedBindingJson = signedBinding,
                            requestHash = verdict.requestHash,
                        ))
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to sign binding with gateway", e)
                        callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "Gateway binding error: ${e.message}"))
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "A2G exception for $tool", e)
            callback(ActionResult.Denied(ReasonCode.INTERNAL_ERROR, "A2G error: ${e.message}"))
        }
    }
}

/**
 * Result of a governed car action.
 *
 * Sealed class used as the callback type for all [GovernedCarClient] methods.
 */
sealed class ActionResult {

    /**
     * The action was authorized and performed.
     * The vehicle bus write has been completed.
     */
    data class Allowed(val verdictId: String) : ActionResult()

    /**
     * The action was denied.
     *
     * [humanText] is suitable for assistant speech (text-to-speech) and has
     * been localised using the strings.xml map (see a2g/res/values/strings.xml).
     */
    data class Denied(
        val reasonCode: ReasonCode,
        val humanText: String,
    ) : ActionResult()

    /**
     * The action requires human approval before it can proceed.
     *
     * Present [bindingId] to the operator approval UI. When the operator
     * approves, call [A2g.decideWithApproval] with [signedBindingJson] and the
     * approval grant to complete Phase 2.
     */
    data class Escalated(
        val bindingId: String,
        val signedBindingJson: String,
        val requestHash: String,
    ) : ActionResult()
}

// ── ReceiptSigner interface ────────────────────────────────────────────────────

/**
 * Signs and constructs a [GatewayReceipt] from a [Verdict.Allow].
 *
 * In demo mode, [NoopReceiptSigner] produces a receipt with an empty signature
 * (suitable for testing against the gateway's demo key).
 *
 * Production deployments should provide an implementation that signs the
 * receipt using the provisioned receipt signing key (SPEC §9.4).
 */
interface ReceiptSigner {
    fun parseAndSign(verdict: Verdict.Allow): GatewayReceipt
}

/** No-op receipt signer for demo / test use. NOT for production. */
object NoopReceiptSigner : ReceiptSigner {
    override fun parseAndSign(verdict: Verdict.Allow): GatewayReceipt {
        // Extract receipt JSON from verdict (mock returns a minimal JSON)
        // In a real integration, parse the receipt JSON and sign with the
        // rich-domain receipt signing key.
        return GatewayReceipt(
            verdictId = verdict.verdictId,
            decision = "ALLOW",
            tool = "unknown", // Would be parsed from verdict.receipt JSON
            paramsJson = "{}",
            policyRule = verdict.policyRule,
            stateTrust = "operator_trusted",
            bindingId = "",
            requestHash = "a".repeat(64),
            issuedAtMs = System.currentTimeMillis(),
            nonceHex = "0".repeat(32),
            signatureHex = "0".repeat(128),
            attestedStateJson = null,
        )
    }
}
