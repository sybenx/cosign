package cc.aaro.cosign

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * What the phone remembers. The membership (share included) is encrypted with
 * an AES key that lives in the Android Keystore and never leaves it. The key
 * needs no unlock, so the background service can answer while the phone is
 * locked; that is a prototype's choice, and the obvious thing to tighten.
 */
class Secrets(context: Context) {
    private val prefs = context.getSharedPreferences("cosign", Context.MODE_PRIVATE)

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun saveMembership(json: String) = save("membership", json)
    fun loadMembership(): String? = load("membership")

    /** Anything small and secret, under [name]: sealed the same way. Null removes it. */
    fun save(name: String, json: String?) {
        if (json == null) return prefs.edit().remove(name).apply()
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = c.iv + c.doFinal(json.toByteArray(Charsets.UTF_8))
        prefs.edit().putString(name, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
    }

    fun load(name: String): String? {
        val sealed = prefs.getString(name, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, 12))
            String(c.doFinal(sealed, 12, sealed.size - 12), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    fun saveLog(json: String) = prefs.edit().putString("log", json).apply()
    fun loadLog(): String? = prefs.getString("log", null)

    fun clear() {
        prefs.edit().clear().apply()
        try { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS) } catch (_: Exception) {}
    }

    private companion object { const val ALIAS = "cosign-membership" }
}
