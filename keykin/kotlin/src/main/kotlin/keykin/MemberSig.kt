// Member-key signing for other protocols, as the TS reference's device/membersig.ts:
// digest = SHA-256(domain ‖ 0x00 ‖ message), signed BIP-340 by the device's own member key, under a
// registered, versioned domain that never begins with keykin or cosign. vectors/membersig.json pins it.
package keykin

object MemberSig {
    private val SHAPE = Regex("^[a-z0-9][a-z0-9.-]*(/[a-z0-9.-]+)*/[0-9]+$")
    private val registered = java.util.concurrent.ConcurrentHashMap.newKeySet<String>().apply { add("nostr-vault/ksig/1") }
    fun fault(domain: String): String? = when {
        domain.length > 128 -> "a domain is a short string"
        domain.startsWith("keykin") || domain.startsWith("cosign") -> "keykin and cosign domains are Keykin Core's own"
        !SHAPE.matches(domain) -> "a domain is lowercase segments ending in a version, like nostr-vault/ksig/1"
        else -> null
    }
    fun register(domain: String) { fault(domain)?.let { refuse("bad_domain", it) }; registered += domain }
    fun digest(domain: String, message: ByteArray): ByteArray {
        fault(domain)?.let { refuse("bad_domain", it) }
        if (domain !in registered) refuse("bad_domain", "$domain is not registered")
        return sha(utf8(domain), byteArrayOf(0), message)
    }
    fun sign(secp: Secp, sk: ByteArray, domain: String, message: ByteArray, aux: ByteArray = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }) =
        secp.schnorrSign(digest(domain, message), sk, aux)
    fun verify(sig: String, domain: String, message: ByteArray, memberKey: String): Boolean =
        try { schnorrVerify(sig, digest(domain, message), memberKey) } catch (_: KeykinException) { false }
}
