// A device's state at rest (core §7.3, §4.5): sealed under a per-membership Android Keystore AES-256-GCM key
// that needs no face, fingerprint or passcode, so the phone signs in the background while locked, and kept
// in `noBackupFilesDir`, never backed up or synced. Destroying the membership deletes the key, after which
// the file is noise.
package keykin.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SealedStore(context: Context, private val name: String) {
    private val file = File(context.noBackupFilesDir, "keykin-$name.sealed")
    private val alias = "keykin-store-$name"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun key(): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setUserAuthenticationRequired(false).build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }
    /** Write `text` sealed: a fresh 12-byte IV ‖ ciphertext ‖ tag, replacing the file atomically. */
    @Synchronized fun save(text: String) {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val out = c.iv + c.doFinal(text.toByteArray(Charsets.UTF_8))
        val tmp = File(file.path + ".tmp"); tmp.writeBytes(out); if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
    }
    @Synchronized fun load(): String? {
        if (!file.exists()) return null
        val b = file.readBytes(); if (b.size < 28) return null
        val k = ks.getKey(alias, null) as? SecretKey ?: return null
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, b.copyOfRange(0, 12))) }
        return String(c.doFinal(b.copyOfRange(12, b.size)), Charsets.UTF_8)
    }
    /** The membership's end: the key goes first, then the file. */
    @Synchronized fun destroy() { ks.deleteEntry(alias); file.delete() }
}
