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

class KeykinException(val code: String, msg: String? = null) : Exception(if (msg == null) code else "$code: $msg") {
    /** For a signing that failed: how many servers demanded an approval (Device policy §2). */
    var demands = 0
}
fun refuse(code: String, msg: String? = null): Nothing = throw KeykinException(code, msg)

/** NIP-01's serialization with §9.5's strings: what the profile refuses is refused, never escaped. */
fun jsJson(v: Any?): String = when (v) {
    null, JSONObject.NULL -> "null"
    is Boolean -> v.toString()
    is Int, is Long -> Json.num(v)
    is String -> Json.str(v)
    is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { jsJson(v.get(it)) }
    is List<*> -> v.joinToString(",", "[", "]") { jsJson(it) }
    else -> refuse("malformed", "json: ${v::class.simpleName}")
}

data class Event(val id: String, val pubkey: String, val createdAt: Long, val kind: Int, val tags: List<List<String>>, val content: String, val sig: String) {
    fun tag(name: String) = tags.firstOrNull { it.isNotEmpty() && it[0] == name }?.getOrNull(1)
    fun json(): JSONObject = JSONObject().put("id", id).put("pubkey", pubkey).put("created_at", createdAt).put("kind", kind)
        .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", sig)
    companion object {
        private val NONE = Event("", "", -1, -1, emptyList(), "", "")
        /** A signed event; one that breaks §9.5's shape becomes an event no id or signature can match. */
        fun of(o: JSONObject): Event = try { shape(o, "signed") } catch (_: KeykinException) { NONE }
        private val HEX64 = Regex("^[0-9a-f]{64}$"); private val HEX128 = Regex("^[0-9a-f]{128}$")
        private val FIELDS = mapOf("signed" to setOf("id", "pubkey", "created_at", "kind", "tags", "content", "sig"), "rumor" to setOf("id", "pubkey", "created_at", "kind", "tags", "content"))
        /** §9.5's event shape: exactly the NIP-01 fields (`rumor` and `cosign`: without `sig`), typed, hex lowercase. */
        fun shape(o: JSONObject, form: String): Event {
            val want = FIELDS[if (form == "signed") "signed" else "rumor"]!!
            for (k in o.keyList()) if (k !in want) refuse("malformed", "the event has a field \"$k\"")
            for (k in want) if (!o.has(k)) refuse("malformed", "the event has no \"$k\"")
            val id = o.get("id") as? String ?: ""; val pk = o.get("pubkey") as? String ?: ""
            if (!HEX64.matches(id)) refuse("malformed", "id: 64 lowercase hex")
            if (!HEX64.matches(pk)) refuse("malformed", "pubkey: 64 lowercase hex")
            val sig = if (form == "signed") (o.get("sig") as? String)?.takeIf { HEX128.matches(it) } ?: refuse("malformed", "sig: 128 lowercase hex") else ""
            val kind = o.get("kind").let { if (Json.isInt(it) && Json.long(it) in 0..65535) Json.long(it).toInt() else refuse("malformed", "kind: an integer from 0 to 65535") }
            val at = o.get("created_at").let { if (Json.isInt(it) && Json.long(it) >= 0) Json.long(it) else refuse("malformed", "created_at: a non-negative integer") }
            val t = o.get("tags") as? JSONArray ?: refuse("malformed", "tags: an array of arrays of strings")
            val tags = (0 until t.length()).map { k -> val a = t.get(k) as? JSONArray ?: refuse("malformed", "tags: an array of arrays of strings")
                (0 until a.length()).map { (a.get(it) as? String)?.also { s -> Json.fault(s)?.let { f -> refuse("malformed", f) } } ?: refuse("malformed", "tags: an array of arrays of strings") } }
            val content = o.get("content") as? String ?: refuse("malformed", "content: a string")
            Json.fault(content)?.let { refuse("malformed", it) }
            return Event(id, pk, at, kind, tags, content, sig)
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
fun verifyEvent(e: Event) = try { e.kind >= 0 && eventId(e) == e.id && schnorrVerify(e.sig, unhex(e.id), e.pubkey) } catch (_: KeykinException) { false }

private val p256: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
/** Strict base64url (§9.5): URL alphabet, no padding, zero unused bits; checked by re-encoding. */
fun b64d(s: String): ByteArray {
    if (!Regex("^[A-Za-z0-9_-]*$").matches(s) || s.length % 4 == 1) refuse("malformed", "base64url")
    val b = Base64.getUrlDecoder().decode(s)
    if (b64u(b) != s) refuse("malformed", "base64url: unused bits")
    return b
}
/** Strict standard base64 with padding (§9.5): length 0 mod 4, at most two `=` at the end, zero unused bits. */
fun b64std(s: String): ByteArray {
    if (s.length % 4 != 0 || !Regex("^[A-Za-z0-9+/]*={0,2}$").matches(s)) refuse("malformed", "base64")
    val b = Base64.getDecoder().decode(s)
    if (Base64.getEncoder().encodeToString(b) != s) refuse("malformed", "base64: unused bits")
    return b
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
    val cd = Json.obj(Json.utf8Strict(clientRaw))
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
