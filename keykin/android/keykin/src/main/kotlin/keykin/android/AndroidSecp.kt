// Every secret-key operation on Android goes through libsecp256k1 (secp256k1-kmp), constant-time, as Cosign
// does: never the BigInteger reference curve, which is for tests and the differential probes only.
package keykin.android

import fr.acinq.secp256k1.Secp256k1
import keykin.N
import keykin.Pt
import keykin.Secp
import keykin.compBytes
import keykin.hex
import keykin.point
import keykin.refuse
import keykin.unhex
import java.math.BigInteger

object AndroidSecp : Secp {
    override fun pub(sk: ByteArray): String = hex(Secp256k1.pubkeyCreate(sk).copyOfRange(1, 33))
    override fun schnorrSign(msg: ByteArray, sk: ByteArray, aux: ByteArray): String = hex(Secp256k1.signSchnorr(msg, sk, aux))
    /** The x coordinate of `sk·P`, P the even-y lift of `pubX` (BIP-340 keys), for NIP-44. */
    override fun ecdhX(sk: ByteArray, pubX: String): ByteArray = Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(unhex("02$pubX")), sk).copyOfRange(1, 33)
    private fun b32(k: BigInteger) = k.mod(N).toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
    /** `k·G` and `k·P` for a secret scalar (a share, a delta, a coefficient): libsecp256k1, constant-time. */
    override fun mulG(k: BigInteger): Pt {
        if (k.mod(N).signum() == 0) refuse("malformed", "the identity")
        return point(hex(Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(b32(k)))))
    }
    override fun mulPoint(k: BigInteger, p: Pt): Pt {
        if (k.mod(N).signum() == 0) refuse("malformed", "the identity")
        return point(hex(Secp256k1.pubKeyCompress(Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(compBytes(p)), b32(k)))))
    }
}
