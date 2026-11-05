// Web Push on the device (core §8.1–§8.3), as the TS reference's src/webpush.ts and src/inbox.ts: one
// address per server and wake class, each with its own RFC 8291 keys; a push decrypted (aes128gcm, one
// last record) and its payload checked against a seated server's host key. On Android the address is a
// UnifiedPush endpoint; the distributor hands the app the body, which goes to `Device.onPush`.
package keykin

import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Push {
    private val spec: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    private fun b32(v: BigInteger) = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
    private fun priv(sk: ByteArray) = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, sk), spec))
    private fun pubKey(raw: ByteArray): java.security.PublicKey {
        if (raw.size != 65 || raw[0] != 4.toByte()) refuse("bad_push", "a key is an uncompressed P-256 point")
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65))), spec))
    }
    /** A fresh address key pair: the raw secret (32 bytes) and the uncompressed public point (65). */
    fun newKey(): Pair<ByteArray, ByteArray> {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return b32((kp.private as ECPrivateKey).s) to pubOf(kp.public as ECPublicKey)
    }
    private fun pubOf(p: ECPublicKey) = byteArrayOf(4) + b32(p.w.affineX) + b32(p.w.affineY)
    /** The public point for a stored secret. */
    fun pubFor(sk: ByteArray): ByteArray = pubOf(KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(SoftLock.p256Mul(BigInteger(1, sk), spec.generator.affineX, spec.generator.affineY).let { ECPoint(it.first, it.second) }, spec)) as ECPublicKey)

    private fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, n: Int) = hmac(hmac(salt, ikm), info + byteArrayOf(1)).copyOf(n)
    private fun info(s: String, vararg rest: ByteArray) = rest.fold(utf8(s) + byteArrayOf(0)) { a, b -> a + b }

    /** RFC 8291 for the device: decrypt with the address's key pair and auth secret. Refuses anything but
     *  one well-formed last record. */
    fun decrypt(body: ByteArray, uaSk: ByteArray, auth: ByteArray): ByteArray {
        if (body.size < 21 + 65 + 17) refuse("bad_push", "short")
        val salt = body.copyOfRange(0, 16)
        val rs = java.nio.ByteBuffer.wrap(body, 16, 4).int.toLong() and 0xffffffffL
        if (body[20].toInt() != 65 || rs < 18) refuse("bad_push", "header")
        val asPub = body.copyOfRange(21, 86); val ct = body.copyOfRange(86, body.size)
        if (ct.size >= rs) refuse("bad_push", "one record only")
        val uaPub = pubFor(uaSk)
        val ecdh = try { KeyAgreement.getInstance("ECDH").apply { init(priv(uaSk)); doPhase(pubKey(asPub), true) }.generateSecret() } catch (e: KeykinException) { throw e } catch (_: Exception) { refuse("bad_push", "sender key") }
        val ikm = hkdf(auth, ecdh, info("WebPush: info", uaPub, asPub), 32)
        val cek = hkdf(salt, ikm, info("Content-Encoding: aes128gcm"), 16); val nonce = hkdf(salt, ikm, info("Content-Encoding: nonce"), 12)
        val padded = try { Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce)) }.doFinal(ct) }
            catch (_: Exception) { refuse("bad_push", "tag") }
        // RFC 8188 §2: the delimiter is the last non-zero byte; after it only zeros.
        var k = padded.size - 1
        while (k >= 0 && padded[k].toInt() == 0) k--
        if (k < 0 || padded[k].toInt() != 2) refuse("bad_push", "padding")
        return padded.copyOfRange(0, k)
    }
    /** §8.2: the payload, signed by a seated server's host key over JCS of everything but `sig`. */
    fun read(plain: ByteArray, hostKeys: Set<String>): JSONObject {
        val p = Json.obj(Json.utf8Strict(plain).trimEnd(' '))
        if (p.optString("srv") !in hostKeys) refuse("unknown_server")
        val rest = JSONObject(p.toString()).also { it.remove("sig") }
        if (!schnorrVerify(p.optString("sig"), sha(utf8(Jcs.of(rest))), p.getString("srv"))) refuse("bad_signature")
        return p
    }
}
