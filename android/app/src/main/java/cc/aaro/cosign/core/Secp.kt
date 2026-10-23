package cc.aaro.cosign.core

import fr.acinq.secp256k1.Secp256k1

/** The secp256k1 operations Nostr needs: x-only keys, BIP-340, and NIP-44's shared x. */
object Secp {
    fun isValidSecret(secret: ByteArray): Boolean =
        secret.size == 32 && try { Secp256k1.secKeyVerify(secret) } catch (_: Exception) { false }

    /** The 32-byte x-only public key. */
    fun publicKey(secret: ByteArray): ByteArray = Secp256k1.pubkeyCreate(secret).copyOfRange(1, 33)

    fun isValidPublicKey(xOnly: ByteArray): Boolean =
        xOnly.size == 32 && try { Secp256k1.pubkeyParse(byteArrayOf(2) + xOnly); true } catch (_: Exception) { false }

    /** The x coordinate of secret × P, P lifted with an even y as BIP-340 does. */
    fun sharedX(secret: ByteArray, xOnly: ByteArray): ByteArray {
        val point = Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(byteArrayOf(2) + xOnly), secret)
        val x = point.copyOfRange(1, 33)
        wipe(point)
        return x
    }

    fun sign(message32: ByteArray, secret: ByteArray, aux32: ByteArray): ByteArray =
        Secp256k1.signSchnorr(message32, secret, aux32)

    fun verify(sig: ByteArray, message32: ByteArray, xOnly: ByteArray): Boolean =
        try { Secp256k1.verifySchnorr(sig, message32, xOnly) } catch (_: Exception) { false }
}
