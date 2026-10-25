package cc.aaro.cosign.core

import java.util.Base64

// Profiles (spec §5). The mechanism never parses a payload itself (P3) and learns
// everything about it through this interface.

sealed class Checked<out T> {
    data class Ok<T>(val value: T) : Checked<T>()
    data class Bad(val reason: String) : Checked<Nothing>()
}

interface Profile<T> {
    val id: String
    val maxPayloadBytes: Int
    val revocable: Boolean
    /** The lowest check level this profile permits (§5, item 7). */
    val minCheck: CodeCheck
    fun encode(value: T): String
    /** P4. */
    fun check(content: String): Checked<T>
    /** P5. */
    fun render(value: T): String
}

/**
 * `nostr-nsec` (profiles/nostr-nsec.md): a whole Nostr identity key.
 *
 * Payload: 64 lowercase hex characters, the 32-byte private scalar. Not bech32.
 * P4: decodes to a scalar in range that yields a valid x-only public key.
 * P5: the npub. Lowest check: `type`. No offline tier.
 */
object NsecProfile : Profile<ByteArray> {
    override val id = "nostr-nsec"
    override val maxPayloadBytes = DEFAULT_MAX_PAYLOAD
    override val revocable = false
    override val minCheck = CodeCheck.TYPE
    private val HEX = Regex("^[0-9a-f]{64}$")

    override fun encode(value: ByteArray): String {
        require(Secp.isValidSecret(value)) { "not a valid key" }
        return value.toHex()
    }

    override fun check(content: String): Checked<ByteArray> {
        if (!HEX.matches(content)) return Checked.Bad("not 64 lowercase hex characters")
        val bytes = content.hexToBytes()
        if (!Secp.isValidSecret(bytes)) return Checked.Bad("not a valid secp256k1 key")
        return Checked.Ok(bytes)
    }

    override fun render(value: ByteArray): String = Nip19.npub(publicKeyHex(value))
}

/**
 * The reference demo's `qrst-demo-text` (src/core/profile.ts in qr-secret-transfer):
 * short made-up text, for checking this app against the live demo page.
 */
object DemoTextProfile : Profile<String> {
    override val id = "qrst-demo-text"
    override val maxPayloadBytes = DEFAULT_MAX_PAYLOAD
    override val revocable = false
    override val minCheck = CodeCheck.NONE

    override fun encode(value: String): String {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty()) { "There is nothing to send." }
        require(bytes.size <= maxPayloadBytes) { "That is ${bytes.size} bytes; the most this profile carries is $maxPayloadBytes." }
        return Base64.getEncoder().encodeToString(bytes)
    }

    override fun check(content: String): Checked<String> {
        val bytes = try { Base64.getDecoder().decode(content) } catch (_: Exception) { return Checked.Bad("not base64") }
        if (bytes.isEmpty() || bytes.size > maxPayloadBytes) return Checked.Bad("size out of range")
        return try {
            Checked.Ok(Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString())
        } catch (_: Exception) {
            Checked.Bad("not text")
        }
    }

    override fun render(value: String): String {
        val cps = value.codePoints().toArray()
        val count = "${cps.size} character${if (cps.size == 1) "" else "s"}"
        val shown = minOf(3, cps.size / 4)
        if (shown == 0) return count
        val start = String(cps, 0, shown).replace(Regex("\\s"), "␣")
        return "$count, starting with “$start”"
    }
}

val PROFILES: Map<String, Profile<*>> = listOf(NsecProfile, DemoTextProfile).associateBy { it.id }
