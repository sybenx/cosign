package cc.aaro.cosign.core

// The commitment and the short authentication string of spec §6.
//
//   commit = SHA-256("qrst-commit" || v || C.pub || nonce_C)
//   code   = SHA-256("qrst-sas" || v || len(p) || p || SND.pub || RCV.pub || nonce_S || nonce_R)
//   digits = (code[0..5] as u40 BE) mod 100_000, zero-padded to 5
//
// SND and RCV are in ROLE order whichever party made contact.

object Sas {
    private val COMMIT_LABEL = "qrst-commit".toByteArray(Charsets.US_ASCII)
    private val SAS_LABEL = "qrst-sas".toByteArray(Charsets.US_ASCII)

    private fun key32(hex: String, what: String): ByteArray {
        require(isHex32(hex)) { "sas: $what must be 32 bytes of lowercase hex" }
        return hex.hexToBytes()
    }

    private fun versionByte(v: Int): ByteArray {
        require(v in 0..255) { "sas: bad version" }
        return byteArrayOf(v.toByte())
    }

    fun commit(v: Int, contactingPub: String, contactingNonce: String): ByteArray =
        sha256(concat(COMMIT_LABEL, versionByte(v), key32(contactingPub, "public key"), key32(contactingNonce, "nonce")))

    fun code(v: Int, profile: String, senderPub: String, receiverPub: String, senderNonce: String, receiverNonce: String): ByteArray {
        require(PROFILE_ID.matches(profile)) { "sas: bad profile identifier" }
        val p = profile.toByteArray(Charsets.US_ASCII)
        return sha256(
            concat(
                SAS_LABEL, versionByte(v), byteArrayOf(p.size.toByte()), p,
                key32(senderPub, "sender public key"), key32(receiverPub, "receiver public key"),
                key32(senderNonce, "sender nonce"), key32(receiverNonce, "receiver nonce"),
            ),
        )
    }

    fun digits(code: ByteArray): String {
        require(code.size >= 5) { "sas: code too short" }
        var n = 0L
        for (i in 0 until 5) n = n * 256 + (code[i].toLong() and 0xff)
        return (n % 100_000).toString().padStart(5, '0')
    }

    fun sas(v: Int, profile: String, senderPub: String, receiverPub: String, senderNonce: String, receiverNonce: String): String =
        digits(code(v, profile, senderPub, receiverPub, senderNonce, receiverNonce))
}
