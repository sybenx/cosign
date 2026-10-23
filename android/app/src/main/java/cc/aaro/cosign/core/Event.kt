package cc.aaro.cosign.core

// Nostr events: ids and BIP-340 signatures. A rumor is an event with an id and no sig.

data class Event(
    val pubkey: String,
    val createdAt: Long,
    val kind: Int,
    val tags: List<List<String>>,
    val content: String,
    val id: String = "",
    val sig: String = "",
) {
    fun serializeForId(): String = Json.stringify(listOf(0, pubkey, createdAt, kind, tags, content))

    fun computeId(): String = sha256(serializeForId().toByteArray(Charsets.UTF_8)).toHex()

    fun withId(): Event = copy(id = computeId())

    /** The event as a JSON object. A rumor carries no `sig` key. */
    fun toMap(): Map<String, Any> = buildMap {
        put("id", id)
        put("pubkey", pubkey)
        put("created_at", createdAt)
        put("kind", kind)
        put("tags", tags)
        put("content", content)
        if (sig.isNotEmpty()) put("sig", sig)
    }

    fun toJson(): String = Json.stringify(toMap())

    fun firstTag(name: String): String? = tags.firstOrNull { it.isNotEmpty() && it[0] == name }?.getOrNull(1)

    /** True when the id is the hash of the event and the signature is valid for its pubkey. */
    fun verify(): Boolean {
        if (!isHex32(id) || !HEX_128.matches(sig)) return false
        if (computeId() != id) return false
        return Secp.verify(sig.hexToBytes(), id.hexToBytes(), pubkey.hexToBytes())
    }

    companion object {
        private val HEX_128 = Regex("^[0-9a-f]{128}$")

        fun sign(pubkey: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String, secret: ByteArray, env: Env): Event {
            val e = Event(pubkey, createdAt, kind, tags, content).withId()
            val sig = Secp.sign(e.id.hexToBytes(), secret, env.random(32)).toHex()
            return e.copy(sig = sig)
        }

        /**
         * Structural check on anything that arrived from outside. Says nothing about
         * signatures. Returns null for anything that is not shaped like an event.
         */
        fun fromMap(value: Any?): Event? {
            val m = value as? Map<*, *> ?: return null
            val pubkey = m["pubkey"] as? String ?: return null
            if (!isHex32(pubkey)) return null
            val createdAt = m["created_at"] as? Long ?: return null
            if (createdAt < 0 || createdAt > 9007199254740991L) return null
            val kind = m["kind"] as? Long ?: return null
            if (kind < 0 || kind > 65535) return null
            val content = m["content"] as? String ?: return null
            val rawTags = m["tags"] as? List<*> ?: return null
            val tags = ArrayList<List<String>>(rawTags.size)
            for (t in rawTags) {
                val tag = t as? List<*> ?: return null
                tags.add(tag.map { it as? String ?: return null })
            }
            val id = m["id"]
            val sig = m["sig"]
            return Event(
                pubkey, createdAt, kind.toInt(), tags, content,
                id = id as? String ?: if (id == null) "" else return null,
                sig = sig as? String ?: if (sig == null) "" else return null,
            )
        }
    }
}

fun generateSecretKey(env: Env): ByteArray {
    while (true) {
        val candidate = env.random(32)
        if (Secp.isValidSecret(candidate)) return candidate
    }
}

fun publicKeyHex(secret: ByteArray): String = Secp.publicKey(secret).toHex()

fun isValidPublicKey(hex: String?): Boolean = isHex32(hex) && Secp.isValidPublicKey(hex!!.hexToBytes())
