package cc.aaro.cosign.core

/** BIP-173 bech32, for npub and nsec. */
object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val GEN = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

    private fun polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) if ((top ushr i) and 1 == 1) chk = chk xor GEN[i]
        }
        return chk
    }

    private fun hrpExpand(hrp: String): IntArray =
        IntArray(hrp.length) { hrp[it].code ushr 5 } + intArrayOf(0) + IntArray(hrp.length) { hrp[it].code and 31 }

    private fun convert(data: ByteArray, from: Int, to: Int, pad: Boolean): ByteArray {
        var acc = 0
        var bits = 0
        val out = ArrayList<Byte>()
        val maxv = (1 shl to) - 1
        for (b in data) {
            val value = b.toInt() and 0xff
            require(value ushr from == 0) { "bech32: bad data" }
            acc = (acc shl from) or value
            bits += from
            while (bits >= to) {
                bits -= to
                out.add(((acc ushr bits) and maxv).toByte())
            }
        }
        if (pad) {
            if (bits > 0) out.add(((acc shl (to - bits)) and maxv).toByte())
        } else {
            require(bits < from && ((acc shl (to - bits)) and maxv) == 0) { "bech32: bad padding" }
        }
        return out.toByteArray()
    }

    fun encode(hrp: String, data: ByteArray): String {
        val words = convert(data, 8, 5, true).map { it.toInt() }.toIntArray()
        val mod = polymod(hrpExpand(hrp) + words + IntArray(6)) xor 1
        val checksum = IntArray(6) { (mod ushr (5 * (5 - it))) and 31 }
        return hrp + "1" + (words + checksum).joinToString("") { CHARSET[it].toString() }
    }

    /** Returns (hrp, data). Throws on a bad checksum, mixed case, or anything malformed. */
    fun decode(input: String, limit: Int = 90): Pair<String, ByteArray> {
        require(input.length <= limit) { "bech32: too long" }
        require(input == input.lowercase() || input == input.uppercase()) { "bech32: mixed case" }
        val s = input.lowercase()
        val pos = s.lastIndexOf('1')
        require(pos >= 1 && pos + 7 <= s.length) { "bech32: no separator" }
        val hrp = s.substring(0, pos)
        val values = IntArray(s.length - pos - 1) {
            val v = CHARSET.indexOf(s[pos + 1 + it])
            require(v >= 0) { "bech32: bad character" }
            v
        }
        require(polymod(hrpExpand(hrp) + values) == 1) { "bech32: bad checksum" }
        val words = values.copyOfRange(0, values.size - 6).map { it.toByte() }.toByteArray()
        return hrp to convert(words, 5, 8, false)
    }
}

object Nip19 {
    fun npub(pubHex: String): String {
        require(isHex32(pubHex)) { "npub: bad public key" }
        return Bech32.encode("npub", pubHex.hexToBytes())
    }

    /** Decodes an npub, verifying the checksum and that the key is a real point. */
    fun npubDecode(npub: String): String {
        val (hrp, data) = Bech32.decode(npub)
        require(hrp == "npub") { "npub: wrong prefix" }
        require(data.size == 32) { "npub: wrong length" }
        require(Secp.isValidPublicKey(data)) { "npub: not a valid key" }
        return data.toHex()
    }

    fun nsec(secret: ByteArray): String = Bech32.encode("nsec", secret)

    /** Accepts an nsec1… or 64 hex characters. Returns the 32 secret bytes, or throws. */
    fun parseSecret(input: String): ByteArray {
        val text = input.trim()
        val bytes = if (text.startsWith("nsec1", ignoreCase = true)) {
            val (hrp, data) = Bech32.decode(text)
            require(hrp == "nsec") { "not an nsec" }
            data
        } else {
            require(Regex("^[0-9a-fA-F]{64}$").matches(text)) { "not an nsec or 64 hex characters" }
            text.lowercase().hexToBytes()
        }
        require(Secp.isValidSecret(bytes)) { "not a valid secp256k1 key" }
        return bytes
    }
}
