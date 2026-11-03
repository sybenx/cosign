// Keykin Core's hash-derived values (core §3.1, §3.2, §4.1, §4.5, §6.1–§6.3, §6.7): the Kotlin
// counterpart of keykin/src/codes.ts, checked against the same docs/keykin/vectors/vectors.json.
package keykin

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
fun unhex(h: String): ByteArray {
    if (h.length % 2 != 0 || h.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) refuse("malformed", "hex")
    return ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}
fun sha(vararg parts: ByteArray): ByteArray { val d = MessageDigest.getInstance("SHA-256"); parts.forEach { d.update(it) }; return d.digest() }
fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)
fun u32(n: Long): ByteArray = ByteBuffer.allocate(4).putInt(n.toInt()).array()
fun u64(n: Long): ByteArray = ByteBuffer.allocate(8).putLong(n).array()
fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

fun hmac(key: ByteArray, data: ByteArray): ByteArray { val m = Mac.getInstance("HmacSHA256"); m.init(SecretKeySpec(key, "HmacSHA256")); return m.doFinal(data) }
/** HKDF-SHA256 with an empty salt, 32 bytes (core §4.5). */
fun hkdf32(ikm: ByteArray, info: ByteArray): ByteArray = hmac(hmac(ByteArray(32), ikm), info + byteArrayOf(1))

private fun six(d: ByteArray) = (ByteBuffer.wrap(d, 0, 8).long.toULong() % 1_000_000uL).toString().padStart(6, '0')
private fun idx30(d: ByteArray) = (1L shl 16) + ((ByteBuffer.wrap(d, 0, 4).int.toLong() and 0xffffffffL) % (1L shl 30))

object Codes {
    fun joinCheck(g: String, m: String, n: String, s: String, t: String) = six(sha(utf8("keykin-join/1"), unhex(g), unhex(m), unhex(n), unhex(s), unhex(t)))
    fun listHash(jcs: String) = hex(sha(utf8(jcs)))
    fun pairCode(g: String, listHash: String, r: String) = six(sha(utf8("keykin-pair/1"), unhex(g), unhex(listHash), unhex(r)))
    fun deviceIndices(g: String, epoch: String, key: String, salt: Long) = (0L..2L).map { idx30(sha(utf8("keykin-index/1"), unhex(g), unhex(epoch), unhex(key), u32(salt), u32(it))) }
    fun helperSeat(g: String) = (0L..2L).map { idx30(sha(utf8("keykin-seat/1"), unhex(g), utf8("helper"), u32(it))) }
    fun holdWaitId(eventId: String) = hex(sha(utf8("hold"), unhex(eventId)))
    fun recoveryWaitId(backup: String, epoch: String, r: String) = hex(sha(utf8("recovery"), unhex(backup), unhex(epoch), unhex(r)))
    fun lockChallenge(g: String, what: ByteArray) = b64u(sha(utf8("keykin-lock/1"), unhex(g), what))
    fun whatSign(eventId: String) = utf8("sign") + unhex(eventId)
    fun whatChange(listHash: String, epoch: String, expiry: Long) = utf8("change") + unhex(listHash) + unhex(epoch) + u64(expiry)
    fun whatCancel(wait: String) = utf8("cancel") + unhex(wait)
    fun waitedDigest(g: String, kind: String, wait: String, start: Long, end: Long) = hex(sha(utf8("keykin-waited/1"), unhex(g), utf8(kind), unhex(wait), u64(start), u64(end)))
    /** §6.7.1: SHA-256 of the sorted 16-byte ids, concatenated. */
    fun stateHash(ids: List<String>) = hex(sha(*ids.distinct().map(::unhex).sortedWith(::cmp).toTypedArray()))
    fun dataKey(base: String, seeds: List<String>) = hex(hkdf32(unhex(base) + seeds.map(::unhex).sortedWith(::cmp).fold(ByteArray(0)) { a, b -> a + b }, utf8("keykin-dk/1")))
    fun signpostD(backup: String) = hex(sha(utf8("keykin-beacon/1"), unhex(backup)))
    fun signpostH(epoch: String, serversJcs: String) = hex(sha(utf8("keykin-beacon/1"), unhex(epoch), utf8(serversJcs)))
    fun signpostDeviceKey(base: String) = hex(hkdf32(unhex(base), utf8("keykin-beacon/1")))
    fun seatedDigest(hKey: String, challenge: ByteArray, ct: ByteArray) = hex(sha(utf8("keykin-seated/1"), unhex(hKey), challenge, ct))
    private fun cmp(a: ByteArray, b: ByteArray): Int { for (i in 0 until minOf(a.size, b.size)) { val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff); if (d != 0) return d }; return a.size - b.size }
}
