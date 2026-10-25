package cc.aaro.cosign.core

// Sealing and gift-wrapping (spec §11.4). Every QRST message is an unsigned rumor,
// sealed (kind 13, signed by the sending burner, NIP-44 to the recipient burner) and
// gift-wrapped (kind 21059, a random one-time signing key, `p` tag set to the
// recipient burner). Two departures from NIP-59, both required by §11.4: every
// timestamp is the true current time, and the wrap carries `expiration` now + 600.

object Wrap {
    fun rumor(kind: Int, tags: List<List<String>>, content: String, senderPub: String, now: Long): Event =
        Event(senderPub, now, kind, tags, content).withId()

    fun wrap(rumor: Event, senderSecret: ByteArray, recipientPub: String, env: Env): Event =
        giftWrap(seal(rumor, senderSecret, recipientPub, env), recipientPub, env)

    fun seal(rumor: Event, senderSecret: ByteArray, recipientPub: String, env: Env): Event {
        require(isHex32(recipientPub)) { "wrap: bad recipient" }
        val key = Nip44.conversationKey(senderSecret, recipientPub)
        try {
            return Event.sign(
                publicKeyHex(senderSecret), env.now(), Kinds.SEAL, emptyList(),
                Nip44.encrypt(rumor.toJson(), key, env.random(32)), senderSecret, env,
            )
        } finally {
            wipe(key)
        }
    }

    /** Wraps a seal under a fresh one-time key, timestamped now. A re-send calls this again on the same seal. */
    fun giftWrap(seal: Event, recipientPub: String, env: Env): Event {
        require(isHex32(recipientPub)) { "wrap: bad recipient" }
        val now = env.now()
        val oneTime = generateSecretKey(env)
        val key = Nip44.conversationKey(oneTime, recipientPub)
        try {
            return Event.sign(
                publicKeyHex(oneTime), now, Kinds.WRAP,
                listOf(listOf("p", recipientPub), listOf("expiration", (now + SESSION_SECONDS).toString())),
                Nip44.encrypt(seal.toJson(), key, env.random(32)), oneTime, env,
            )
        } finally {
            wipe(oneTime, key)
        }
    }

    sealed class Unwrapped {
        data class Ok(val rumor: Event) : Unwrapped()
        data class Failed(val reason: String) : Unwrapped()
    }

    private fun open(secret: ByteArray, peerPub: String, content: String): String? {
        var key: ByteArray? = null
        return try {
            key = Nip44.conversationKey(secret, peerPub)
            Nip44.decrypt(content, key)
        } catch (_: Exception) {
            null
        } finally {
            wipe(key)
        }
    }

    /**
     * Opens a gift wrap addressed to `recipientSecret`. On success the rumor's `pubkey`
     * is the burner that signed the seal: that equality is the attribution check (T5).
     */
    fun unwrap(event: Event, recipientSecret: ByteArray): Unwrapped {
        if (event.kind != Kinds.WRAP) return Unwrapped.Failed("not-a-wrap")
        val own = publicKeyHex(recipientSecret)
        if (event.tags.none { it.size >= 2 && it[0] == "p" && it[1] == own }) return Unwrapped.Failed("not-for-us")
        if (!event.verify()) return Unwrapped.Failed("bad-wrap-signature")

        val sealJson = open(recipientSecret, event.pubkey, event.content) ?: return Unwrapped.Failed("undecryptable")
        val seal = Event.fromMap(Json.parse(sealJson))
        if (seal == null || seal.kind != Kinds.SEAL || !seal.verify()) return Unwrapped.Failed("bad-seal")

        val rumorJson = open(recipientSecret, seal.pubkey, seal.content) ?: return Unwrapped.Failed("undecryptable")
        val inner = Event.fromMap(Json.parse(rumorJson)) ?: return Unwrapped.Failed("bad-rumor")
        // The sending burner appears in no other field (§11.4, attribution check).
        if (inner.pubkey != seal.pubkey) return Unwrapped.Failed("attribution")
        val rumor = Event(inner.pubkey, inner.createdAt, inner.kind, inner.tags, inner.content)
        val id = rumor.computeId()
        if (inner.id.isNotEmpty() && inner.id != id) return Unwrapped.Failed("bad-rumor")
        return Unwrapped.Ok(rumor.copy(id = id))
    }
}
