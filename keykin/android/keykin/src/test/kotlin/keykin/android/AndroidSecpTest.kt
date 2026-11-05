package keykin.android

import keykin.Secp
import keykin.hex
import org.junit.Assert.assertEquals
import org.junit.Test

/** libsecp256k1 agrees with the reference curve the vectors were checked with. */
class AndroidSecpTest {
    @Test fun sameAsTheReference() {
        val rnd = java.security.SecureRandom()
        repeat(20) {
            val sk = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val other = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val msg = ByteArray(32).also(rnd::nextBytes); val aux = ByteArray(32).also(rnd::nextBytes)
            assertEquals(Secp.Reference.pub(sk), AndroidSecp.pub(sk))
            assertEquals(Secp.Reference.schnorrSign(msg, sk, aux), AndroidSecp.schnorrSign(msg, sk, aux))
            assertEquals(hex(Secp.Reference.ecdhX(sk, Secp.Reference.pub(other))), hex(AndroidSecp.ecdhX(sk, AndroidSecp.pub(other))))
            val k = java.math.BigInteger(1, sk); val p = Secp.Reference.mulG(java.math.BigInteger(1, other))
            assertEquals(Secp.Reference.mulG(k), AndroidSecp.mulG(k))
            assertEquals(Secp.Reference.mulPoint(k, p), AndroidSecp.mulPoint(k, p))
        }
    }
}
