package ai.vanaras.a2g

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A2G gateway transport interface.
 *
 * The default implementation uses a Unix domain socket with CBOR-framed messages
 * matching the Rust transport in a2g-gateway/src/transport.rs.
 *
 * A vsock implementation (for hypervisor-isolated AAOS Safety Island deployments)
 * is the documented extension point for future work (ADR-0021 open questions).
 */
interface GatewayTransport : Closeable {
    /**
     * Send a [GatewayRequest] and receive a [GatewayResponse].
     *
     * The connection is opened for each request (one request per connection,
     * matching the server's per-connection handler model).
     */
    @Throws(IOException::class)
    fun sendRequest(request: GatewayRequest): GatewayResponse
}

/**
 * CBOR-framed length-prefixed gateway transport over a Unix domain socket.
 *
 * Frame layout (matches a2g-gateway/src/transport.rs exactly):
 * ```
 * ┌───────────────────────┬─────────────────────────────────┐
 * │  length (4 B, BE u32) │  CBOR-serialized payload (N B)  │
 * └───────────────────────┴─────────────────────────────────┘
 * ```
 * Maximum frame size: 64 KiB (same as MAX_FRAME_BYTES in Rust).
 *
 * @param socketPath Path to the gateway Unix domain socket (e.g. "/tmp/a2g.sock").
 */
class UnixSocketTransport(private val socketPath: String) : GatewayTransport {

    companion object {
        /** Maximum CBOR frame size — must match Rust MAX_FRAME_BYTES = 64 KiB. */
        const val MAX_FRAME_BYTES = 64 * 1024
    }

    override fun sendRequest(request: GatewayRequest): GatewayResponse {
        // Unix domain sockets via Java: use LocalSocket on Android,
        // or net.unix on JVM (host tests use a mock transport).
        // On Android, use android.net.LocalSocket.
        return sendRequestInternal(request)
    }

    /**
     * Internal implementation using android.net.LocalSocket for Android, or
     * falling back to a reflective approach for host JVM tests.
     *
     * On Android (minSdk 29): android.net.LocalSocket / LocalSocketAddress
     * are available and support FILESYSTEM namespace.
     *
     * For host unit tests, override [GatewayTransport] with a mock.
     */
    @Throws(IOException::class)
    private fun sendRequestInternal(request: GatewayRequest): GatewayResponse {
        try {
            val localSocketClass = Class.forName("android.net.LocalSocket")
            val localSocketAddressClass = Class.forName("android.net.LocalSocketAddress")
            val namespaceClass = localSocketAddressClass.declaredClasses
                .firstOrNull { it.simpleName == "Namespace" }
                ?: throw IOException("Cannot find LocalSocketAddress.Namespace")
            val filesystemField = namespaceClass.getField("FILESYSTEM")
            val namespace = filesystemField.get(null)

            val addressCtor = localSocketAddressClass.getConstructor(
                String::class.java, namespaceClass
            )
            val address = addressCtor.newInstance(socketPath, namespace)

            val socket = localSocketClass.newInstance()
            val connectMethod = localSocketClass.getMethod(
                "connect", localSocketAddressClass
            )
            connectMethod.invoke(socket, address)

            val outputStream = localSocketClass.getMethod("getOutputStream")
                .invoke(socket) as java.io.OutputStream
            val inputStream = localSocketClass.getMethod("getInputStream")
                .invoke(socket) as java.io.InputStream

            try {
                writeFrame(outputStream, request)
                return readFrame(inputStream)
            } finally {
                localSocketClass.getMethod("close").invoke(socket)
            }
        } catch (e: ClassNotFoundException) {
            throw IOException(
                "android.net.LocalSocket not available (host JVM?). " +
                    "Use a mock GatewayTransport in tests.", e
            )
        }
    }

    override fun close() {
        // Stateless transport — each request opens and closes its own connection.
    }

    // ── CBOR frame encoding / decoding ──────────────────────────────────────────

    /**
     * Encode [request] to CBOR and write as a length-prefixed frame.
     *
     * The Kotlin CBOR encoder uses the same serde-derived tag names as the Rust
     * GatewayRequest enum, so the tag string is compatible across the boundary.
     */
    @Throws(IOException::class)
    private fun writeFrame(out: java.io.OutputStream, request: GatewayRequest) {
        val cbor = CborCodec.encodeRequest(request)
        if (cbor.size > MAX_FRAME_BYTES) {
            throw IOException("Request frame too large: ${cbor.size} bytes (max $MAX_FRAME_BYTES)")
        }
        val lenBytes = ByteBuffer.allocate(4)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(cbor.size)
            .array()
        out.write(lenBytes)
        out.write(cbor)
        out.flush()
    }

    @Throws(IOException::class)
    private fun readFrame(inp: java.io.InputStream): GatewayResponse {
        val lenBytes = ByteArray(4)
        var read = 0
        while (read < 4) {
            val n = inp.read(lenBytes, read, 4 - read)
            if (n < 0) throw IOException("Gateway disconnected while reading frame length")
            read += n
        }
        val len = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).int
        if (len < 0 || len > MAX_FRAME_BYTES) {
            throw IOException("Gateway frame too large: $len bytes (max $MAX_FRAME_BYTES)")
        }
        val body = ByteArray(len)
        var bodyRead = 0
        while (bodyRead < len) {
            val n = inp.read(body, bodyRead, len - bodyRead)
            if (n < 0) throw IOException("Gateway disconnected while reading frame body")
            bodyRead += n
        }
        return CborCodec.decodeResponse(body)
    }
}

// ── Gateway request / response types ──────────────────────────────────────────

/**
 * Wire messages from the rich domain to the Enforcing Gateway.
 *
 * These map exactly to the Rust GatewayRequest enum in
 * a2g-gateway/src/protocol.rs. The tag string in the CBOR encoding is the
 * Rust variant name.
 */
sealed class GatewayRequest {
    /** Ask the gateway to sign an unsigned Phase 1 PendingApprovalBinding. */
    data class SignBinding(val bindingJson: String) : GatewayRequest()

    /** Submit an ApprovalGrant to approve a queued binding. */
    data class SubmitGrant(val grantJson: String) : GatewayRequest()

    /** Present a signed GatewayReceipt for enforcement on the bus. */
    data class Enforce(val receipt: GatewayReceipt) : GatewayRequest()

    /** Retrieve verifying public keys (demo/bootstrap only). */
    object GetPublicKeys : GatewayRequest()
}

/**
 * Wire messages from the Enforcing Gateway to the rich domain.
 *
 * Maps to the Rust GatewayResponse enum in a2g-gateway/src/protocol.rs.
 */
sealed class GatewayResponse {
    data class SignedBinding(val signedJson: String) : GatewayResponse()
    data class GrantAccepted(val bindingId: String) : GatewayResponse()
    data class Enforced(
        val verdictId: String,
        val frameHex: String,
        val realWrite: Boolean,
    ) : GatewayResponse()
    data class Refused(val reason: String) : GatewayResponse()
    data class PublicKeys(
        val receiptVerifyingKeyHex: String,
        val attesterVerifyingKeyHex: String,
        val operatorVerifyingKeyHex: String,
        val bindingVerifyingKeyHex: String,
    ) : GatewayResponse()
    data class Error(val message: String) : GatewayResponse()
}

/**
 * Gateway receipt — the artifact the rich domain presents to the Enforcing
 * Gateway for bus-write authorization (SPEC §9.4).
 *
 * Matches the Rust GatewayReceipt struct in a2g-gateway/src/protocol.rs.
 */
data class GatewayReceipt(
    val verdictId: String,
    val decision: String,
    val tool: String,
    val paramsJson: String,
    val policyRule: String,
    val stateTrust: String,
    val bindingId: String,
    val requestHash: String,
    val issuedAtMs: Long,
    val nonceHex: String,
    val signatureHex: String,
    val attestedStateJson: String? = null,
)

// ── High-level GatewayClient ───────────────────────────────────────────────────

/**
 * High-level client for the A2G Enforcing Gateway.
 *
 * Provides convenience methods for the three main gateway operations:
 * 1. [signBinding] — Phase 1 HITL: gateway signs an unsigned binding.
 * 2. [enforce] — Present a signed receipt for bus-write authorization.
 * 3. [getPublicKeys] — Bootstrap: retrieve the gateway's verifying keys.
 *
 * @param transport The underlying transport. Default: [UnixSocketTransport].
 */
class GatewayClient(private val transport: GatewayTransport) : Closeable {

    /**
     * Ask the gateway to sign a Phase 1 PendingApprovalBinding.
     *
     * @param unsignedBindingJson The unsigned binding JSON from [Verdict.Escalate.unsignedBindingJson].
     * @return The gateway-signed binding JSON to pass to [A2g.decideWithApproval].
     * @throws IOException on connection error.
     * @throws GatewayRefusedException if the gateway refuses to sign.
     */
    @Throws(IOException::class, GatewayRefusedException::class)
    fun signBinding(unsignedBindingJson: String): String {
        val resp = transport.sendRequest(GatewayRequest.SignBinding(unsignedBindingJson))
        return when (resp) {
            is GatewayResponse.SignedBinding -> resp.signedJson
            is GatewayResponse.Refused -> throw GatewayRefusedException(resp.reason)
            is GatewayResponse.Error -> throw IOException("Gateway error: ${resp.message}")
            else -> throw IOException("Unexpected gateway response: $resp")
        }
    }

    /**
     * Present a [GatewayReceipt] for enforcement on the protected resource.
     *
     * The gateway performs 7-step verification (SPEC §9.5) before any bus write.
     *
     * @param receipt The signed receipt for an ALLOW verdict.
     * @return [GatewayResponse.Enforced] on success.
     * @throws GatewayRefusedException if the gateway refuses (any verification step failed).
     * @throws IOException on connection error.
     */
    @Throws(IOException::class, GatewayRefusedException::class)
    fun enforce(receipt: GatewayReceipt): GatewayResponse.Enforced {
        val resp = transport.sendRequest(GatewayRequest.Enforce(receipt))
        return when (resp) {
            is GatewayResponse.Enforced -> resp
            is GatewayResponse.Refused -> throw GatewayRefusedException(resp.reason)
            is GatewayResponse.Error -> throw IOException("Gateway error: ${resp.message}")
            else -> throw IOException("Unexpected gateway response: $resp")
        }
    }

    /**
     * Retrieve the gateway's verifying public keys.
     *
     * Use during bootstrap to obtain the binding verifying key for Phase 2.
     *
     * @return [GatewayResponse.PublicKeys] containing the key bundle.
     */
    @Throws(IOException::class)
    fun getPublicKeys(): GatewayResponse.PublicKeys {
        val resp = transport.sendRequest(GatewayRequest.GetPublicKeys)
        return when (resp) {
            is GatewayResponse.PublicKeys -> resp
            is GatewayResponse.Error -> throw IOException("Gateway error: ${resp.message}")
            else -> throw IOException("Unexpected gateway response: $resp")
        }
    }

    override fun close() = transport.close()
}

/** Thrown when the Enforcing Gateway refuses a request (any step in §9.5 failed). */
class GatewayRefusedException(reason: String) :
    IOException("Gateway refused: $reason")

// ── CBOR codec (minimal inline implementation) ─────────────────────────────────

/**
 * Minimal CBOR codec for GatewayRequest / GatewayResponse.
 *
 * Uses a hand-written encoder rather than pulling in a CBOR library dependency,
 * keeping the SDK's transitive dependency footprint small. Only the map variant
 * encoding (serde externally-tagged enums) is needed for gateway communication.
 *
 * The Rust gateway uses serde + ciborium for CBOR. The serde "externally tagged"
 * representation of an enum variant `Variant { field: value }` is:
 *   CBOR map with one key "Variant" → map { "field": value }
 *
 * For [GatewayRequest.GetPublicKeys] (unit variant): "GetPublicKeys" → {}
 *
 * Note: for production use, replace this with the `cbor2` or similar library.
 * The hand-written codec covers exactly the request/response types used by the
 * gateway protocol — no more, no less.
 */
internal object CborCodec {

    fun encodeRequest(req: GatewayRequest): ByteArray = when (req) {
        is GatewayRequest.SignBinding -> encodeTaggedMap(
            "SignBinding", mapOf("binding_json" to req.bindingJson)
        )
        is GatewayRequest.SubmitGrant -> encodeTaggedMap(
            "SubmitGrant", mapOf("grant_json" to req.grantJson)
        )
        is GatewayRequest.Enforce -> encodeTaggedMap(
            "Enforce", mapOf("receipt" to encodeReceipt(req.receipt))
        )
        is GatewayRequest.GetPublicKeys -> encodeTaggedMap("GetPublicKeys", emptyMap())
    }

    fun decodeResponse(bytes: ByteArray): GatewayResponse {
        // Decode the outer map: { "VariantName" => inner_value }
        val (variantName, inner) = decodeOuterMap(bytes)
        return when (variantName) {
            "SignedBinding" -> GatewayResponse.SignedBinding(
                signedJson = (inner as Map<*, *>)["signed_json"] as? String ?: ""
            )
            "GrantAccepted" -> GatewayResponse.GrantAccepted(
                bindingId = (inner as Map<*, *>)["binding_id"] as? String ?: ""
            )
            "Enforced" -> {
                val m = inner as Map<*, *>
                GatewayResponse.Enforced(
                    verdictId = m["verdict_id"] as? String ?: "",
                    frameHex = m["frame_hex"] as? String ?: "",
                    realWrite = m["real_write"] as? Boolean ?: false,
                )
            }
            "Refused" -> GatewayResponse.Refused(
                reason = (inner as Map<*, *>)["reason"] as? String ?: ""
            )
            "PublicKeys" -> {
                val m = inner as Map<*, *>
                GatewayResponse.PublicKeys(
                    receiptVerifyingKeyHex = m["receipt_verifying_key_hex"] as? String ?: "",
                    attesterVerifyingKeyHex = m["attester_verifying_key_hex"] as? String ?: "",
                    operatorVerifyingKeyHex = m["operator_verifying_key_hex"] as? String ?: "",
                    bindingVerifyingKeyHex = m["binding_verifying_key_hex"] as? String ?: "",
                )
            }
            "Error" -> GatewayResponse.Error(
                message = (inner as Map<*, *>)["message"] as? String ?: ""
            )
            else -> GatewayResponse.Error("Unknown variant: $variantName")
        }
    }

    // ── Minimal CBOR primitives ────────────────────────────────────────────────

    private fun encodeTaggedMap(tag: String, fields: Map<String, Any>): ByteArray {
        // Outer map: 1 entry { tag => fields_map }
        val outerMap = mutableListOf<Byte>()
        // Map with 1 entry: 0xa1
        outerMap.add(0xa1.toByte())
        outerMap.addAll(encodeText(tag).toList())
        outerMap.addAll(encodeMap(fields).toList())
        return outerMap.toByteArray()
    }

    private fun encodeMap(fields: Map<String, Any>): ByteArray {
        val out = mutableListOf<Byte>()
        // Map header
        out.addAll(encodeMapHeader(fields.size).toList())
        for ((k, v) in fields) {
            out.addAll(encodeText(k).toList())
            out.addAll(encodeValue(v).toList())
        }
        return out.toByteArray()
    }

    private fun encodeMapHeader(size: Int): ByteArray = when {
        size <= 23 -> byteArrayOf((0xa0 + size).toByte())
        size <= 255 -> byteArrayOf(0xb8.toByte(), size.toByte())
        else -> throw IOException("Map too large for minimal CBOR encoder")
    }

    private fun encodeText(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val header = encodeHeader(3, bytes.size) // major type 3 = text string
        return header + bytes
    }

    private fun encodeBytes(b: ByteArray): ByteArray {
        val header = encodeHeader(2, b.size) // major type 2 = byte string
        return header + b
    }

    private fun encodeHeader(majorType: Int, len: Int): ByteArray = when {
        len <= 23 -> byteArrayOf(((majorType shl 5) + len).toByte())
        len <= 255 -> byteArrayOf(
            ((majorType shl 5) + 24).toByte(),
            len.toByte()
        )
        len <= 65535 -> byteArrayOf(
            ((majorType shl 5) + 25).toByte(),
            (len shr 8).toByte(),
            len.toByte()
        )
        else -> byteArrayOf(
            ((majorType shl 5) + 26).toByte(),
            (len shr 24).toByte(),
            (len shr 16).toByte(),
            (len shr 8).toByte(),
            len.toByte()
        )
    }

    private fun encodeValue(v: Any): ByteArray = when (v) {
        is String -> encodeText(v)
        is ByteArray -> encodeBytes(v)
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            encodeMap(v as Map<String, Any>)
        }
        is Boolean -> if (v) byteArrayOf(0xf5.toByte()) else byteArrayOf(0xf4.toByte())
        else -> encodeText(v.toString())
    }

    private fun encodeReceipt(r: GatewayReceipt): Map<String, Any> = buildMap {
        put("verdict_id", r.verdictId)
        put("decision", r.decision)
        put("tool", r.tool)
        put("params_json", r.paramsJson)
        put("policy_rule", r.policyRule)
        put("state_trust", r.stateTrust)
        put("binding_id", r.bindingId)
        put("request_hash", r.requestHash)
        put("issued_at_ms", r.issuedAtMs.toString()) // simplified: encode as string
        put("nonce_hex", r.nonceHex)
        put("signature_hex", r.signatureHex)
        r.attestedStateJson?.let { put("attested_state_json", it) }
    }

    // ── Minimal CBOR decoder for gateway responses ─────────────────────────────

    /**
     * Decode the outermost CBOR map (serde externally-tagged enum).
     * Returns (variantName, innerValue).
     */
    private fun decodeOuterMap(bytes: ByteArray): Pair<String, Any?> {
        val reader = CborReader(bytes)
        val mapSize = reader.readMapHeader()
        if (mapSize != 1) {
            throw IOException("Expected 1-entry outer map, got $mapSize entries")
        }
        val variantName = reader.readText()
        val inner = reader.readValue()
        return Pair(variantName, inner)
    }
}

/** Simple streaming CBOR reader for gateway response decoding. */
private class CborReader(private val data: ByteArray) {
    private var pos = 0

    fun readMapHeader(): Int {
        val b = nextByte().toInt() and 0xFF
        val major = b shr 5
        if (major != 5) throw IOException("Expected CBOR map (major 5), got major $major at pos ${pos - 1}")
        return readAdditional(b and 0x1F)
    }

    fun readText(): String {
        val b = nextByte().toInt() and 0xFF
        val major = b shr 5
        if (major != 3) throw IOException("Expected CBOR text (major 3), got major $major")
        val len = readAdditional(b and 0x1F)
        val bytes = readBytes(len)
        return String(bytes, Charsets.UTF_8)
    }

    fun readValue(): Any? {
        val b = data[pos].toInt() and 0xFF
        val major = b shr 5
        return when (major) {
            0 -> { pos++; readAdditional(b and 0x1F) } // unsigned int
            2 -> { pos++; val len = readAdditional(b and 0x1F); readBytes(len) } // bytes
            3 -> readText() // text
            4 -> { // array
                pos++
                val len = readAdditional(b and 0x1F)
                (0 until len).map { readValue() }
            }
            5 -> { // map
                pos++
                val len = readAdditional(b and 0x1F)
                val result = mutableMapOf<String, Any?>()
                repeat(len) {
                    val key = readText()
                    result[key] = readValue()
                }
                result
            }
            7 -> { // simple values
                pos++
                when (b and 0x1F) {
                    20 -> false
                    21 -> true
                    22 -> null
                    else -> null
                }
            }
            else -> {
                pos++
                null
            }
        }
    }

    private fun nextByte(): Byte {
        if (pos >= data.size) throw IOException("Unexpected end of CBOR data")
        return data[pos++]
    }

    private fun readAdditional(info: Int): Int = when {
        info <= 23 -> info
        info == 24 -> (nextByte().toInt() and 0xFF)
        info == 25 -> {
            val hi = (nextByte().toInt() and 0xFF) shl 8
            val lo = (nextByte().toInt() and 0xFF)
            hi or lo
        }
        info == 26 -> {
            var v = 0
            repeat(4) { v = (v shl 8) or (nextByte().toInt() and 0xFF) }
            v
        }
        else -> throw IOException("Unsupported CBOR additional info: $info")
    }

    private fun readBytes(len: Int): ByteArray {
        if (pos + len > data.size) throw IOException("Not enough CBOR data for $len bytes")
        val result = data.copyOfRange(pos, pos + len)
        pos += len
        return result
    }
}
