// Event ids (NIP-01), BIP-340 verification and lock assertions (core §6.1) for the Kotlin port.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

class KeykinException(val code: String, msg: String? = null) : Exception(if (msg == null) code else "$code: $msg")
fun refuse(code: String, msg: String? = null): Nothing = throw KeykinException(code, msg)

/** JSON as JavaScript's JSON.stringify writes it, which NIP-01 ids hash. */
fun jsJson(v: Any?): String = when (v) {
    null, JSONObject.NULL -> "null"
    is Boolean -> v.toString()
    is Number -> Json.num(v)
    is String -> Json.str(v)
    is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { jsJson(v.get(it)) }
    is List<*> -> v.joinToString(",", "[", "]") { jsJson(it) }
    else -> error("json: ${v::class}")
}

data class Event(val id: String, val pubkey: String, val createdAt: Long, val kind: Int, val tags: List<List<String>>, val content: String, val sig: String) {
    fun tag(name: String) = tags.firstOrNull { it.isNotEmpty() && it[0] == name }?.getOrNull(1)
    companion object {
        fun of(o: JSONObject): Event {
            val t = o.getJSONArray("tags")
            // created_at and kind are integers; anything else gives an event no id can match.
            if (!Json.isInt(o.opt("created_at")) || !Json.isInt(o.opt("kind"))) return Event("", "", -1, -1, emptyList(), "", "")
            return Event(o.optString("id"), o.optString("pubkey"), Json.long(o.opt("created_at")), Json.long(o.opt("kind")).toInt(),
                (0 until t.length()).map { k -> val a = t.getJSONArray(k); (0 until a.length()).map { a.getString(it) } }, o.optString("content"), o.optString("sig"))
        }
    }
}
fun eventId(e: Event) = hex(sha(utf8(jsJson(listOf(0, e.pubkey, e.createdAt, e.kind, e.tags, e.content)))))

private fun taggedHash(tag: String, vararg parts: ByteArray): ByteArray { val t = sha(utf8(tag)); return sha(t, t, *parts) }
private fun liftX(x: BigInteger): Pt? {
    if (x >= P) return null
    val y2 = (x.pow(3) + BigInteger.valueOf(7)).mod(P); val y = y2.modPow((P + BigInteger.ONE).shiftRight(2), P)
    if (y.modPow(BigInteger.TWO, P) != y2) return null
    return Pt(x, if (y.testBit(0)) P - y else y)
}
fun liftXHex(h: String): Pt = liftX(BigInteger(h, 16)) ?: refuse("malformed", "x-only key")
private fun b32(v: BigInteger) = unhex(v.toString(16).padStart(64, '0'))
/** BIP-340 verification. */
fun schnorrVerify(sigHex: String, msg: ByteArray, pubHex: String): Boolean = try {
    val sig = unhex(sigHex); require(sig.size == 64); require(unhex(pubHex).size == 32)
    val Pk = liftX(BigInteger(pubHex, 16))!!; val r = BigInteger(1, sig.copyOfRange(0, 32)); val s = BigInteger(1, sig.copyOfRange(32, 64))
    require(r < P && s < N)
    val e = BigInteger(1, taggedHash("BIP0340/challenge", b32(r), unhex(pubHex), msg)).mod(N)
    val R = add(mul(s), mul(N - e, Pk))
    R != null && !R.y.testBit(0) && R.x == r
} catch (_: Exception) { false }
fun verifyEvent(e: Event) = eventId(e) == e.id && schnorrVerify(e.sig, unhex(e.id), e.pubkey)

private val p256: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
private fun b64d(s: String): ByteArray {
    if (!Regex("^[A-Za-z0-9_-]*$").matches(s) || s.length % 4 == 1) refuse("malformed", "base64url")
    return Base64.getUrlDecoder().decode(s)
}
/** Strict DER for an ECDSA signature: SEQUENCE of two positive, minimal INTEGERs (as noble checks). */
private fun derOk(b: ByteArray): Boolean {
    fun u(k: Int) = b[k].toInt() and 0xff
    if (b.size < 8 || u(0) != 0x30 || u(1) != b.size - 2) return false
    var k = 2
    repeat(2) {
        if (k + 2 > b.size || u(k) != 0x02) return false
        val l = u(k + 1); if (l == 0 || k + 2 + l > b.size) return false
        if (u(k + 2) and 0x80 != 0) return false
        if (l > 1 && u(k + 2) == 0 && u(k + 3) and 0x80 == 0) return false
        k += 2 + l
    }
    return k == b.size
}
/** §6.1: null when `assertion` is a valid lock signature over `what`, else why not. */
fun checkAssertion(g: String, lockPub: String, rp: String, w: ByteArray, a: JSONObject): String? = try {
    if (!Regex("^04[0-9a-f]{128}$").matches(lockPub) || !Regex("^[0-9a-f]{64}$").matches(rp)) refuse("malformed")
    val authData = b64d(a.getString("authData")); val clientRaw = b64d(a.getString("clientData")); val sig = b64d(a.getString("sig"))
    val cd = Json.obj(String(clientRaw, Charsets.UTF_8))
    when {
        cd.optString("type") != "webauthn.get" -> "lock_type"
        cd.optString("challenge") != Codes.lockChallenge(g, w) -> "lock_challenge"
        authData.size < 37 || !authData.copyOfRange(0, 32).contentEquals(unhex(rp)) -> "lock_rp"
        (authData[32].toInt() and 0x05) != 0x05 -> "lock_flags"
        else -> {
            val pub = unhex(lockPub); require(pub.size == 65 && pub[0] == 4.toByte())
            val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, pub.copyOfRange(1, 33)), BigInteger(1, pub.copyOfRange(33, 65))), p256))
            val v = Signature.getInstance("SHA256withECDSA"); v.initVerify(key); v.update(authData + sha(clientRaw))
            if (derOk(sig) && v.verify(sig)) null else "lock_sig"
        }
    }
} catch (_: Exception) { "lock_malformed" }
