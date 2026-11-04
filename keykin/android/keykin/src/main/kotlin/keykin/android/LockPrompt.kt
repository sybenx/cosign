// The lock's approval on Android (core §6.1): the library owns the BiometricPrompt, as the plan says, and the
// app only shows it. The Keystore key signs only inside the prompt (BIOMETRIC_STRONG, CryptoObject), so the
// approval exists only once the person's face or finger matched. Run from an activity in the signer process.
package keykin.android

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import keykin.Approve
import keykin.Device
import org.json.JSONArray
import org.json.JSONObject

object LockPrompt {
    /** Whether this phone can hold a lock: a strong biometric enrolled. A passcode-only phone is lockless. */
    fun available(a: FragmentActivity) = BiometricManager.from(a).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** Ask for the person's biometric to approve `list` with `lock`; `done` gets the approval, or null if they
     *  cancelled or it failed. `title` and `subtitle` say what is being approved, in the app's words. */
    fun approveList(a: FragmentActivity, d: Device, lock: KeystoreLock, list: JSONArray, title: String, subtitle: String, done: (JSONObject?) -> Unit) {
        val expiry = System.currentTimeMillis() / 1000 + 3600
        val pending = try { lock.begin(d.g, Approve.changeWhat(list, d.epochId, expiry)) } catch (_: Exception) { return done(null) }
        val prompt = BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                done(try { JSONObject().put("expiry", expiry).put("lock", JSONObject().put("member", d.pub).put("assertion", lock.finish(pending))) } catch (_: Exception) { null })
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) = done(null)
        })
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel").build(),
            BiometricPrompt.CryptoObject(pending.signature))
    }
}
