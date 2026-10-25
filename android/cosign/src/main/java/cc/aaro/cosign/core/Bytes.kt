package cc.aaro.cosign.core

import java.security.MessageDigest
import java.security.SecureRandom

private val HEX = "0123456789abcdef".toCharArray()
private val HEX_64 = Regex("^[0-9a-f]{64}$")

fun ByteArray.toHex(): String {
    val out = CharArray(size * 2)
    for (i in indices) {
        val b = this[i].toInt() and 0xff
        out[i * 2] = HEX[b ushr 4]
        out[i * 2 + 1] = HEX[b and 0x0f]
    }
    return String(out)
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex: odd length" }
    return ByteArray(length / 2) { i ->
        val hi = Character.digit(this[i * 2], 16)
        val lo = Character.digit(this[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "hex: bad digit" }
        ((hi shl 4) or lo).toByte()
    }
}

/** True for exactly 32 bytes of lowercase hex, the form every key and nonce takes on the wire. */
fun isHex32(value: String?): Boolean = value != null && HEX_64.matches(value)

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var at = 0
    for (p in parts) {
        p.copyInto(out, at)
        at += p.size
    }
    return out
}

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

/** Constant-time comparison of two byte strings of the same length. */
fun equalBytes(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

/** Constant-time comparison of two short ASCII strings of the same length. */
fun equalAscii(a: String, b: String): Boolean {
    if (a.length != b.length) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
    return diff == 0
}

/** Overwrites buffers we own. The JVM may have copied them earlier, so this is best effort. */
fun wipe(vararg buffers: ByteArray?) {
    for (b in buffers) b?.fill(0)
}

/** Source of randomness and the clock, injected so that a whole flow can be replayed in a test. */
interface Env {
    fun random(length: Int): ByteArray
    fun now(): Long
}

object SystemEnv : Env {
    private val rng = SecureRandom()
    override fun random(length: Int): ByteArray = ByteArray(length).also { rng.nextBytes(it) }
    override fun now(): Long = System.currentTimeMillis() / 1000
}
