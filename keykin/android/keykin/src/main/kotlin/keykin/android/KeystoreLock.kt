// The lock (core §6.1) on Android: an Android Keystore P-256 key usable only after a strong biometric
// (BIOMETRIC_STRONG, invalidated when a new fingerprint or face is enrolled), signing the same
// WebAuthn-shaped assertion the reference checks: authData = SHA-256(rpId) ‖ flags (UP|UV) ‖ counter,
// clientData = {type: "webauthn.get", challenge, origin}, sig = ECDSA-P256-SHA256 (DER) over
// authData ‖ SHA-256(clientData). A phone with only a passcode has no lock: it is a lockless device.
//
// The key signs only inside a BiometricPrompt: the app calls `begin(g, what)`, shows the prompt with
// `BiometricPrompt.CryptoObject(begin.signature)`, and on success calls `finish(begin)`. `assert` is the
// synchronous form for a signature the prompt already unlocked (`Device.approveLock` calls it).
package keykin.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import keykin.Codes
import keykin.Lock
import keykin.b64u
import keykin.hex
import keykin.refuse
import keykin.sha
import keykin.u32
import keykin.utf8
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class KeystoreLock private constructor(val alias: String, val rpId: String) : Lock {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun b32(v: BigInteger) = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
    override val pub: JSONObject = (ks.getCertificate(alias)?.publicKey as? ECPublicKey ?: refuse("no_lock", "no Keystore key $alias")).let { k ->
        JSONObject().put("pub", "04" + hex(b32(k.w.affineX)) + hex(b32(k.w.affineY))).put("rp", hex(sha(utf8(rpId))))
    }
    private var counter = 0L

    /** A signing in progress: its authData and clientData, and the Keystore signature the prompt unlocks. */
    class Pending(val authData: ByteArray, val clientData: ByteArray, val signature: Signature)
    fun begin(g: String, what: ByteArray): Pending {
        val authData = sha(utf8(rpId)) + byteArrayOf(0x05) + u32(++counter)
        val clientData = utf8(JSONObject().put("type", "webauthn.get").put("challenge", Codes.lockChallenge(g, what)).put("origin", "keykin:android").toString())
        val s = Signature.getInstance("SHA256withECDSA").apply { initSign(ks.getKey(alias, null) as java.security.PrivateKey) }
        return Pending(authData, clientData, s)
    }
    /** After the prompt succeeded: the assertion. */
    fun finish(p: Pending): JSONObject {
        p.signature.update(p.authData + sha(p.clientData))
        return JSONObject().put("authData", b64u(p.authData)).put("clientData", b64u(p.clientData)).put("sig", b64u(p.signature.sign()))
    }
    /** For a key made without a prompt (`requireBiometric = false`, tests only), or a pending signing the
     *  prompt just unlocked (`unlocked`). */
    @Volatile var unlocked: ((String, ByteArray) -> Pending)? = null
    override fun assert(g: String, what: ByteArray): JSONObject = finish(unlocked?.invoke(g, what) ?: begin(g, what))

    companion object {
        /** The lock for `alias`, made if it doesn't exist. `requireBiometric = false` only for an emulator test. */
        fun open(alias: String, rpId: String = "keykin.android", requireBiometric: Boolean = true): KeystoreLock {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(alias)) {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
                if (requireBiometric) spec.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG).setInvalidatedByBiometricEnrollment(true)
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec.build()) }.generateKeyPair()
            }
            return KeystoreLock(alias, rpId)
        }
        fun exists(alias: String) = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)
        fun destroy(alias: String) { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias) }
    }
}
