// Every secret-key operation on Android goes through libsecp256k1 (secp256k1-kmp), constant-time, as Cosign
// does: never the BigInteger reference curve, which is for tests and the differential probes only.
package keykin.android

import fr.acinq.secp256k1.Secp256k1
import keykin.Secp
import keykin.hex
import keykin.unhex

object AndroidSecp : Secp {
    override fun pub(sk: ByteArray): String = hex(Secp256k1.pubkeyCreate(sk).copyOfRange(1, 33))
    override fun schnorrSign(msg: ByteArray, sk: ByteArray, aux: ByteArray): String = hex(Secp256k1.signSchnorr(msg, sk, aux))
    /** The x coordinate of `sk·P`, P the even-y lift of `pubX` (BIP-340 keys), for NIP-44. */
    override fun ecdhX(sk: ByteArray, pubX: String): ByteArray = Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(unhex("02$pubX")), sk).copyOfRange(1, 33)
    /** `k·G`, compressed. */
    fun mulG(k: ByteArray): ByteArray = Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(k))
    /** `k·P` for a compressed point, compressed. */
    fun mulPoint(k: ByteArray, p33: ByteArray): ByteArray = Secp256k1.pubKeyCompress(Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(p33), k))
}
