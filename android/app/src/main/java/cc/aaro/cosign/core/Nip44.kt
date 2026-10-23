package cc.aaro.cosign.core

import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// NIP-44 version 2: the encryption both layers of a gift wrap use (spec §11.1, T3).
// Checked in test/ against the official vector file.

object Nip44 {
    private val SALT = "nip44-v2".toByteArray(Charsets.US_ASCII)
    private const val MIN_PLAINTEXT = 1
    private const val MAX_PLAINTEXT = 65535

    fun hmac(key: ByteArray, vararg data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (d in data) mac.update(d)
        return mac.doFinal()
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var at = 0
        var counter = 1
        while (at < length) {
            t = hmac(prk, t, info, byteArrayOf(counter.toByte()))
            val n = minOf(t.size, length - at)
            t.copyInto(out, at, 0, n)
            at += n
            counter++
        }
        return out
    }

    /** The shared key for one ordered pair of keys. Symmetric: (a, B) and (b, A) agree. */
    fun conversationKey(secret: ByteArray, publicKeyHex: String): ByteArray {
        require(isHex32(publicKeyHex)) { "nip44: bad public key" }
        val x = Secp.sharedX(secret, publicKeyHex.hexToBytes())
        val key = hmac(SALT, x) // HKDF-extract(salt, ikm)
        wipe(x)
        return key
    }

    fun paddedLength(length: Int): Int {
        require(length >= 1) { "nip44: bad length" }
        if (length <= 32) return 32
        val nextPower = Integer.highestOneBit(length - 1) shl 1
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * ((length - 1) / chunk + 1)
    }

    private fun pad(plaintext: String): ByteArray {
        val bytes = plaintext.toByteArray(Charsets.UTF_8)
        val n = bytes.size
        require(n in MIN_PLAINTEXT..MAX_PLAINTEXT) { "nip44: plaintext length out of range" }
        val out = ByteArray(2 + paddedLength(n))
        out[0] = (n ushr 8).toByte()
        out[1] = (n and 0xff).toByte()
        bytes.copyInto(out, 2)
        return out
    }

    private fun unpad(padded: ByteArray): String {
        val n = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        require(n in MIN_PLAINTEXT..MAX_PLAINTEXT && padded.size >= 2 + n && padded.size == 2 + paddedLength(n)) { "nip44: bad padding" }
        val decoder = Charsets.UTF_8.newDecoder()
        return decoder.decode(java.nio.ByteBuffer.wrap(padded, 2, n)).toString()
    }

    fun encrypt(plaintext: String, conversation: ByteArray, nonce: ByteArray): String {
        require(conversation.size == 32 && nonce.size == 32) { "nip44: bad key or nonce" }
        val keys = hkdfExpand(conversation, nonce, 76)
        val padded = pad(plaintext)
        val ciphertext = ChaCha20.xor(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), padded)
        val mac = hmac(keys.copyOfRange(44, 76), nonce, ciphertext)
        wipe(keys, padded)
        return Base64.getEncoder().encodeToString(concat(byteArrayOf(2), nonce, ciphertext, mac))
    }

    fun decrypt(payload: String, conversation: ByteArray): String {
        require(payload.isNotEmpty() && payload[0] != '#') { "nip44: unknown version" }
        require(payload.length in 132..87472) { "nip44: bad payload size" }
        val data = try { Base64.getDecoder().decode(payload) } catch (_: IllegalArgumentException) { throw IllegalArgumentException("nip44: bad base64") }
        require(data.size in 99..65603) { "nip44: bad data size" }
        require(data[0].toInt() == 2) { "nip44: unknown version" }
        val nonce = data.copyOfRange(1, 33)
        val ciphertext = data.copyOfRange(33, data.size - 32)
        val mac = data.copyOfRange(data.size - 32, data.size)
        val keys = hkdfExpand(conversation, nonce, 76)
        val expected = hmac(keys.copyOfRange(44, 76), nonce, ciphertext)
        if (!equalBytes(expected, mac)) {
            wipe(keys)
            throw IllegalArgumentException("nip44: bad mac")
        }
        val padded = ChaCha20.xor(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), ciphertext)
        wipe(keys)
        try {
            return unpad(padded)
        } finally {
            wipe(padded)
        }
    }
}

/** RFC 8439 ChaCha20 with a 12-byte nonce and the counter starting at 0, as NIP-44 uses it. */
object ChaCha20 {
    private fun rotl(v: Int, n: Int) = (v shl n) or (v ushr (32 - n))

    private fun le(b: ByteArray, i: Int) =
        (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8) or
            ((b[i + 2].toInt() and 0xff) shl 16) or ((b[i + 3].toInt() and 0xff) shl 24)

    fun xor(key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12)
        val state = IntArray(16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = le(key, i * 4)
        state[12] = 0
        for (i in 0 until 3) state[13 + i] = le(nonce, i * 4)
        val out = ByteArray(input.size)
        val x = IntArray(16)
        val block = ByteArray(64)
        var at = 0
        while (at < input.size) {
            state.copyInto(x)
            repeat(10) {
                qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
                qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
            }
            for (i in 0 until 16) {
                val v = x[i] + state[i]
                block[i * 4] = v.toByte(); block[i * 4 + 1] = (v ushr 8).toByte()
                block[i * 4 + 2] = (v ushr 16).toByte(); block[i * 4 + 3] = (v ushr 24).toByte()
            }
            val n = minOf(64, input.size - at)
            for (i in 0 until n) out[at + i] = (input[at + i].toInt() xor block[i].toInt()).toByte()
            at += n
            state[12]++
        }
        x.fill(0); state.fill(0); block.fill(0)
        return out
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }
}
