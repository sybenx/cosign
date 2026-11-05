// Device names (Account admin §2, "Names"), as the TS reference's device/labels.ts: one account-signed kind 30078 event
// per device, `d = "keykin-labels:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF(base data key, "keykin-labels-d/1"), member
// key))`, its content XChaCha20-Poly1305 under HKDF-SHA256(dk(S), "keykin-labels/1") with associated data `g ‖ d ‖ state`,
// as base64(nonce ‖ ciphertext); inside, the name and model signed by the named device's own member key. "Last seen" is
// this device's own observation and is never published.
package keykin

import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

object Labels {
    const val KIND = 30078
    private const val MAX = 64
    private val rnd = SecureRandom()
    data class Label(val name: String, val model: String, val at: Long) {
        fun json(): JSONObject = JSONObject().put("name", name).put("model", model).put("at", at)
    }

    fun d(baseDk: String, member: String) = "keykin-labels:" + hex(hmac(hkdf32(unhex(baseDk), utf8("keykin-labels-d/1")), unhex(member)).copyOf(16))
    private fun contentKey(dk: ByteArray) = hkdf32(dk, utf8("keykin-labels/1"))
    private fun aad(g: String, d: String, state: String) = unhex(g) + utf8(d) + unhex(state)
    fun digest(g: String, member: String, l: Label): ByteArray = sha(utf8("keykin-label/1"), unhex(g), unhex(member), sha(utf8(Jcs.of(l.json()))))
    private fun ok(s: String) = s.length <= MAX && s.none { it.code < 0x20 || it.code == 0x7f }

    /** A name as the person typed it: trimmed, 1–64 characters, no control characters; a model of at most 64. */
    fun clean(name: String, model: String): Pair<String, String> {
        val n = name.trim(); val m = model.trim()
        if (n.isEmpty() || !ok(n) || !ok(m)) refuse("malformed", "a name of 1–64 characters, and a model of at most 64")
        return n to m
    }

    /** This device's label event, unsigned (the account signs it). */
    fun event(g: String, memberSk: ByteArray, baseDk: String, state: String, dk: ByteArray, l: Label, createdAt: Long): Unsigned {
        val member = Keykin.secp.pub(memberSk)
        val d = d(baseDk, member)
        val text = Jcs.of(l.json().put("sig", Keykin.secp.schnorrSign(digest(g, member, l), memberSk, ByteArray(32).also(rnd::nextBytes))))
        val box = XChaCha.seal(contentKey(dk), ByteArray(24).also(rnd::nextBytes), utf8(text), aad(g, d, state))
        return Unsigned(g, createdAt, KIND, listOf(listOf("d", d), listOf("state", state)), Base64.getEncoder().encodeToString(box))
    }

    /** `member`'s label among `events`: account-signed, opened under its state's data key, signed by `member`; of those,
     *  the highest `at` (`created_at` breaks a tie): a replayed older label never wins (Account admin draft 9 §2). */
    fun read(g: String, member: String, baseDk: String, keyFor: (String) -> ByteArray?, events: List<Event>): Label? {
        val d = d(baseDk, member)
        var best: Pair<Label, Long>? = null
        for (e in events.filter { it.kind == KIND && it.pubkey == g && it.tag("d") == d && verifyEvent(it) }) try {
            val state = e.tag("state") ?: ""
            val key = keyFor(state) ?: continue
            val x = Json.obj(Json.utf8Strict(XChaCha.open(contentKey(key), Base64.getDecoder().decode(e.content), aad(g, d, state))))
            val name = x.opt("name") as? String ?: continue; val model = x.opt("model") as? String ?: continue
            val at = (x.opt("at") as? Number)?.toLong() ?: continue
            if (name.isEmpty() || !ok(name) || !ok(model)) continue
            val l = Label(name, model, at)
            if (!schnorrVerify(x.optString("sig"), digest(g, member, l), member)) continue
            val b = best
            if (b == null || l.at > b.first.at || (l.at == b.first.at && e.createdAt > b.second)) best = l to e.createdAt
        } catch (_: Exception) { /* one we can't open, or a forgery */ }
        return best?.first
    }
}
