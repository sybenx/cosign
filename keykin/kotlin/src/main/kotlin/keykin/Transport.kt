// The envelope (core §9.1) for the Kotlin device side: BIP-340 signing, NIP-44 v2 (decrypted to bytes,
// then fatal UTF-8, §9.5), and NIP-59's rumor (kind 24301) sealed (kind 13) and gift-wrapped (21059 live,
// 1059 stored) to the recipient. The same checks as the TS reference's transport.ts `unwrap`.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.SecureRandom

/** Secret-key operations. `Reference` is plain BigInteger arithmetic, not constant-time: tests and the
 *  differential probes only. An Android build plugs in libsecp256k1 (secp256k1-kmp), as Cosign does. */
interface Secp {
    fun pub(sk: ByteArray): String
    fun schnorrSign(msg: ByteArray, sk: ByteArray, aux: ByteArray): String
    /** The shared point's x coordinate (32 bytes), for NIP-44's conversation key. */
    fun ecdhX(sk: ByteArray, pubX: String): ByteArray

    object Reference : Secp {
        private fun d(sk: ByteArray) = BigInteger(1, sk).also { require(it.signum() > 0 && it < N) { "secret key out of range" } }
        private fun b32(v: BigInteger) = unhex(v.toString(16).padStart(64, '0'))
        private fun tagged(tag: String, vararg parts: ByteArray): ByteArray { val t = sha(utf8(tag)); return sha(t, t, *parts) }
        override fun pub(sk: ByteArray): String = mul(d(sk))!!.x.toString(16).padStart(64, '0')
        override fun schnorrSign(msg: ByteArray, sk: ByteArray, aux: ByteArray): String {
            // BIP-340, as written.
            val d0 = d(sk); val P0 = mul(d0)!!; val dd = if (P0.y.testBit(0)) N - d0 else d0
            val t = b32(dd).zip(tagged("BIP0340/aux", aux).toList()) { a, b -> (a.toInt() xor b.toInt()).toByte() }.toByteArray()
            val px = b32(P0.x)
            val k0 = BigInteger(1, tagged("BIP0340/nonce", t, px, msg)).mod(N)
            require(k0.signum() != 0) { "nonce is zero" }
            val R = mul(k0)!!; val k = if (R.y.testBit(0)) N - k0 else k0
            val e = BigInteger(1, tagged("BIP0340/challenge", b32(R.x), px, msg)).mod(N)
            return hex(b32(R.x) + b32((k + e * dd).mod(N)))
        }
        override fun ecdhX(sk: ByteArray, pubX: String): ByteArray = b32(mul(d(sk), liftXHex(pubX))!!.x)
    }
}

/** RFC 8439's ChaCha20 (12-byte nonce, counter from 0), written out: Android has no plain ChaCha20 everywhere. */
object ChaCha20 {
    private fun rotl(v: Int, c: Int) = (v shl c) or (v ushr (32 - c))
    private fun le(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)
    fun xor(key: ByteArray, nonce: ByteArray, data: ByteArray, counter: Int = 0): ByteArray {
        require(key.size == 32 && nonce.size == 12)
        val s = IntArray(16)
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
        for (i in 0 until 8) s[4 + i] = le(key, 4 * i)
        for (i in 0 until 3) s[13 + i] = le(nonce, 4 * i)
        val out = ByteArray(data.size); var ctr = counter; var off = 0
        val x = IntArray(16)
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16); x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8); x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
        }
        while (off < data.size) {
            s[12] = ctr++
            s.copyInto(x)
            repeat(10) { qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15); qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14) }
            for (i in 0 until 16) {
                val w = x[i] + s[i]
                for (j in 0 until 4) { val p = off + 4 * i + j; if (p < data.size) out[p] = (data[p].toInt() xor ((w ushr (8 * j)) and 0xff)).toByte() }
            }
            off += 64
        }
        return out
    }
}

/** XChaCha20-Poly1305 (core §7.2's release-seed wrap: nonce ‖ ciphertext ‖ tag), written out like ChaCha20:
 *  HChaCha20 for the subkey, then RFC 8439's AEAD with no associated data. Only opening is needed here. */
object XChaCha {
    private fun rotl(v: Int, c: Int) = (v shl c) or (v ushr (32 - c))
    private fun le(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)
    fun hchacha(key: ByteArray, nonce16: ByteArray): ByteArray {
        val x = IntArray(16)
        x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574
        for (i in 0 until 8) x[4 + i] = le(key, 4 * i)
        for (i in 0 until 4) x[12 + i] = le(nonce16, 4 * i)
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16); x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8); x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
        }
        repeat(10) { qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15); qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14) }
        val out = ByteArray(32)
        for ((k, w) in (intArrayOf(x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15])).withIndex()) for (j in 0 until 4) out[4 * k + j] = (w ushr (8 * j)).toByte()
        return out
    }
    private val P1305 = BigInteger.ONE.shiftLeft(130) - BigInteger.valueOf(5)
    private fun leNum(b: ByteArray) = BigInteger(1, b.reversedArray())
    fun poly1305(key: ByteArray, msg: ByteArray): ByteArray {
        val rb = key.copyOfRange(0, 16)
        for (i in intArrayOf(3, 7, 11, 15)) rb[i] = (rb[i].toInt() and 15).toByte()
        for (i in intArrayOf(4, 8, 12)) rb[i] = (rb[i].toInt() and 252).toByte()
        val r = leNum(rb); val sKey = leNum(key.copyOfRange(16, 32))
        var acc = BigInteger.ZERO
        for (o in msg.indices step 16) acc = ((acc + leNum(msg.copyOfRange(o, minOf(o + 16, msg.size)) + byteArrayOf(1))) * r).mod(P1305)
        val t = (acc + sKey).toByteArray().reversedArray().copyOf(16)
        return t
    }
    private fun pad16(n: Int) = ByteArray((16 - n % 16) % 16)
    private fun le64(n: Long) = ByteArray(8) { (n ushr (8 * it)).toByte() }
    /** Open `nonce(24) ‖ ciphertext ‖ tag(16)` under `key`; refuses a bad tag. */
    fun open(key: ByteArray, box: ByteArray): ByteArray {
        if (box.size < 40) refuse("malformed", "a sealed box")
        val sub = hchacha(key, box.copyOfRange(0, 16))
        val n12 = ByteArray(4) + box.copyOfRange(16, 24)
        val ct = box.copyOfRange(24, box.size - 16); val tag = box.copyOfRange(box.size - 16, box.size)
        val polyKey = ChaCha20.xor(sub, n12, ByteArray(32), 0)
        val mac = poly1305(polyKey, ct + pad16(ct.size) + le64(0) + le64(ct.size.toLong()))
        if (!java.security.MessageDigest.isEqual(mac, tag)) refuse("bad_box", "the tag does not match")
        return ChaCha20.xor(sub, n12, ct, 1)
    }
}

/** NIP-44 v2. */
object Nip44 {
    private fun expand(prk: ByteArray, info: ByteArray, len: Int): ByteArray {
        var t = ByteArray(0); var out = ByteArray(0); var i = 1
        while (out.size < len) { t = hmac(prk, t + info + byteArrayOf(i.toByte())); out += t; i++ }
        return out.copyOf(len)
    }
    fun conversationKey(secp: Secp, sk: ByteArray, pubX: String): ByteArray = hmac(utf8("nip44-v2"), secp.ecdhX(sk, pubX))
    private fun paddedLen(len: Int): Int {
        if (len <= 32) return 32
        val next = Integer.highestOneBit(len - 1) shl 1
        val chunk = if (next <= 256) 32 else next / 8
        return chunk * ((len - 1) / chunk + 1)
    }
    fun encrypt(plain: String, ck: ByteArray, nonce: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }): String {
        val p = utf8(plain)
        require(p.isNotEmpty() && p.size <= 65535) { "NIP-44 plaintext is 1 to 65535 bytes" }
        val keys = expand(ck, nonce, 76)
        val padded = ByteArray(2 + paddedLen(p.size)); padded[0] = (p.size shr 8).toByte(); padded[1] = p.size.toByte(); p.copyInto(padded, 2)
        val ct = ChaCha20.xor(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), padded)
        val mac = hmac(keys.copyOfRange(44, 76), nonce + ct)
        return java.util.Base64.getEncoder().encodeToString(byteArrayOf(2) + nonce + ct + mac)
    }
    /** The plaintext bytes, or `undecryptable`: padded standard base64 with zero unused bits, version 2,
     *  a constant-time MAC check, NIP-44's two-byte length and its padding. */
    fun decryptBytes(payload: String, ck: ByteArray): ByteArray {
        if (payload.length < 132 || payload.length > 87472) refuse("undecryptable", "payload length")
        val d = try { b64std(payload) } catch (_: KeykinException) { refuse("undecryptable", "payload base64") }
        if (d.size < 99 || d[0].toInt() != 2) refuse("undecryptable", "version")
        val nonce = d.copyOfRange(1, 33); val ct = d.copyOfRange(33, d.size - 32); val mac = d.copyOfRange(d.size - 32, d.size)
        val keys = expand(ck, nonce, 76)
        if (!java.security.MessageDigest.isEqual(hmac(keys.copyOfRange(44, 76), nonce + ct), mac)) refuse("undecryptable", "mac")
        val padded = ChaCha20.xor(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), ct)
        val len = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        if (len < 1 || padded.size != 2 + paddedLen(len)) refuse("undecryptable", "padding")
        return padded.copyOfRange(2, 2 + len)
    }
    fun decrypt(payload: String, ck: ByteArray): String = Json.utf8Strict(decryptBytes(payload, ck))
}

/** NIP-59 as Core uses it (§9.1). */
class Envelope(private val secp: Secp = Secp.Reference, private val rnd: SecureRandom = SecureRandom()) {
    private fun rand(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }
    /** A signed event as JSON, its id by NIP-01 and its signature by BIP-340. */
    fun sign(sk: ByteArray, kind: Int, createdAt: Long, tags: List<List<String>>, content: String): JSONObject {
        val pub = secp.pub(sk)
        val id = eventId(Event("", pub, createdAt, kind, tags, content, ""))
        val sig = secp.schnorrSign(unhex(id), sk, rand(32))
        return JSONObject().put("id", id).put("pubkey", pub).put("created_at", createdAt).put("kind", kind)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", sig)
    }
    /** Seal `body` (a JSON object, written as JCS) from `senderSk` to `to`, and wrap it with a fresh key. */
    fun wrap(senderSk: ByteArray, to: String, body: JSONObject, at: Long, stored: Boolean = false): JSONObject {
        val pub = secp.pub(senderSk)
        val content = Jcs.of(body)
        val rumorId = eventId(Event("", pub, at, 24301, emptyList(), content, ""))
        val rumor = JSONObject().put("id", rumorId).put("pubkey", pub).put("created_at", at).put("kind", 24301).put("tags", JSONArray()).put("content", content)
        val seal = sign(senderSk, 13, at, emptyList(), Nip44.encrypt(Jcs.of(rumor), Nip44.conversationKey(secp, senderSk, to)))
        val eph = rand(32)
        return sign(eph, if (stored) 1059 else 21059, at, listOf(listOf("p", to)), Nip44.encrypt(Jcs.of(seal), Nip44.conversationKey(secp, eph, to)))
    }
    data class Opened(val from: String, val body: JSONObject, val sentAt: Long)
    /** Open a wrap addressed to us. Each text through §9.5 on its own; the seal's key is the sender and
     *  must be the rumor's pubkey; the rumor's id is recomputed. */
    fun unwrap(sk: ByteArray, w: JSONObject): Opened {
        val wrapEv = Event.of(w)
        if (wrapEv.kind != 21059 && wrapEv.kind != 1059) refuse("not_a_wrap")
        if (!verifyEvent(wrapEv)) refuse("bad_wrap")
        val sealJ: JSONObject; val rumorJ: JSONObject; val seal: Event
        try {
            sealJ = Json.obj(Nip44.decrypt(wrapEv.content, Nip44.conversationKey(secp, sk, wrapEv.pubkey)))
            seal = Event.of(sealJ)
            if (seal.kind != 13 || !verifyEvent(seal)) refuse("bad_seal")
            rumorJ = Json.obj(Nip44.decrypt(seal.content, Nip44.conversationKey(secp, sk, seal.pubkey)))
        } catch (e: KeykinException) { refuse(if (e.code == "bad_seal") "bad_seal" else e.code) }
        val rumor = Event.shape(rumorJ, "rumor")
        if (rumor.kind != 24301 || rumor.pubkey != seal.pubkey || eventId(rumor) != rumor.id) refuse("bad_rumor")
        return Opened(seal.pubkey, Json.obj(rumor.content), rumor.createdAt)
    }
}

/** Messages over 24,000 bytes travel as `part` rumors (core §9.1), as the TS reference splits and
 *  reassembles them, with the same caps (review 10 H3). */
object Parts {
    const val PART_BYTES = 24_000; const val MAX_MESSAGE = 512 * 1024
    const val TTL_S = 600L; const val PER_SENDER = 4; const val OPEN = 256
    private val LIFETIME = mapOf("sign" to 60L, "ask" to 120L, "member" to 7 * 86400L)
    fun split(body: JSONObject): List<JSONObject> {
        val bytes = utf8(Jcs.of(body))
        if (bytes.size > MAX_MESSAGE) refuse("too_large")
        if (bytes.size <= PART_BYTES) return listOf(body)
        val of = hex(ByteArray(16).also { SecureRandom().nextBytes(it) }); val m = (bytes.size + PART_BYTES - 1) / PART_BYTES
        return (0 until m).map { k -> JSONObject().put("v", 1).put("type", "part").put("of", of).put("k", k).put("m", m).put("cls", body.opt("cls") ?: JSONObject.NULL)
            .put("data", java.util.Base64.getEncoder().encodeToString(bytes.copyOfRange(k * PART_BYTES, minOf(bytes.size, (k + 1) * PART_BYTES)))) }
    }
    class Reassembler {
        private class Open(val first: Long, val cls: String, val got: Array<ByteArray?>) { var size = 0 }
        private val open = LinkedHashMap<String, Open>()
        /** The whole message once every part is here, null while parts are missing, the body itself if it isn't a part. */
        fun take(from: String, body: JSONObject, at: Long): JSONObject? {
            prune(at)
            if (body.optString("type") != "part") return body
            val k = body.opt("k"); val m = body.opt("m")
            if (!Json.isInt(k) || !Json.isInt(m)) refuse("bad_part")
            val kk = Json.long(k); val mm = Json.long(m)
            if (kk < 0 || kk >= mm || mm > (MAX_MESSAGE + PART_BYTES - 1) / PART_BYTES + 1) refuse("bad_part")
            val key = "$from:${body.opt("of")}"
            val cls = body.optString("cls").takeIf { it in LIFETIME } ?: "sign"
            var p = open[key]
            if (p == null) {
                if (open.size >= OPEN) refuse("too_many_parts")
                if (open.keys.count { it.startsWith("$from:") } >= PER_SENDER) refuse("too_many_parts")
                p = Open(at, cls, arrayOfNulls(mm.toInt()))
            }
            if (p.got.size.toLong() != mm) refuse("bad_part")
            val data = b64std(body.opt("data") as? String ?: refuse("malformed", "part data"))
            if (data.size > PART_BYTES) refuse("bad_part")
            if (p.got[kk.toInt()] == null) { p.got[kk.toInt()] = data; p.size += data.size }
            if (p.size > MAX_MESSAGE) { open.remove(key); refuse("too_large") }
            open[key] = p
            if (p.got.any { it == null }) return null
            open.remove(key)
            return Json.obj(Json.utf8Strict(p.got.fold(ByteArray(0)) { a, b -> a + b!! }))
        }
        fun prune(at: Long) { open.entries.removeIf { at - it.value.first > minOf(LIFETIME[it.value.cls]!! + 30, TTL_S) } }
        val pending: Int get() = open.size
    }
}
