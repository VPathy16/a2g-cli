package ai.vanaras.a2g

/**
 * Declares which mandate issuers are accepted by the decision engine.
 *
 * Mirrors the [a2g_trust_anchor_self_sovereign] / [a2g_trust_anchor_roots]
 * C ABI constructors (ADR-0014). Passing a TrustAnchor is mandatory — there
 * is no implicit default. A null or missing anchor produces A2G_DECISION_ERROR
 * in the native layer (fail-explicit).
 *
 * @see A2g.init
 */
sealed class TrustAnchor {

    /**
     * Accepts any mandate whose signature is self-consistent (the mandate's
     * issuer_pubkey matches its issuer_did and signature).
     *
     * Use only when issuer trust is explicitly waived — e.g., local development
     * and integration testing. NOT suitable for production deployments where
     * mandates are issued by a provisioned fleet authority.
     *
     * This is the [a2g_trust_anchor_self_sovereign] C ABI call.
     */
    object SelfSovereign : TrustAnchor()

    /**
     * Accepts only mandates whose issuer_pubkey matches one of the supplied
     * 32-byte ed25519 public keys.
     *
     * Each ByteArray in [pubkeys] MUST be exactly 32 bytes. The list MUST be
     * non-empty. Violations produce null from the C ABI ([a2g_trust_anchor_roots]
     * returns NULL on empty or null input), which [A2g] maps to an exception.
     *
     * This is the [a2g_trust_anchor_roots] C ABI call.
     */
    data class Roots(val pubkeys: List<ByteArray>) : TrustAnchor() {
        init {
            require(pubkeys.isNotEmpty()) { "Roots trust anchor requires at least one pubkey" }
            pubkeys.forEach { key ->
                require(key.size == 32) {
                    "Each pubkey in Roots must be exactly 32 bytes; got ${key.size}"
                }
            }
        }
    }
}
