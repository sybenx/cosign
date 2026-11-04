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

    /** Ask for the person's biometric to approve `list` with `lock`; `done` gets the approval, or null and why:
     *  "cancelled", "failed", or "invalidated" (a new face or finger was enrolled: the lock must be replaced,
     *  core §6.1, review 15 L3). `title` and `subtitle` say what is being approved, in the app's words. */
    fun approveList(a: FragmentActivity, d: Device, lock: KeystoreLock, list: JSONArray, title: String, subtitle: String, done: (JSONObject?, String?) -> Unit) {
        val expiry = System.currentTimeMillis() / 1000 + 3600
        val pending = try { lock.begin(d.g, Approve.changeWhat(list, d.epochId, expiry)) }
            catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) { return done(null, "invalidated") }
            catch (_: Exception) { return done(null, "failed") }
        val prompt = BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                try { done(JSONObject().put("expiry", expiry).put("lock", JSONObject().put("member", d.pub).put("assertion", lock.finish(pending))), null) } catch (_: Exception) { done(null, "failed") }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) = done(null, "cancelled")
        })
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel").build(),
            BiometricPrompt.CryptoObject(pending.signature))
    }

    /** Ask for the person's biometric to approve signing the held event `eventId` (core §5.8): `done` gets the
     *  approval (`{"lock": {member, assertion}}` over "sign" ‖ event id), or null and why, as approveList. */
    fun approveSign(a: FragmentActivity, d: Device, lock: KeystoreLock, eventId: String, title: String, subtitle: String, done: (JSONObject?, String?) -> Unit) {
        val pending = try { lock.begin(d.g, keykin.Codes.whatSign(eventId)) }
            catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) { return done(null, "invalidated") }
            catch (_: Exception) { return done(null, "failed") }
        val prompt = BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                try { done(JSONObject().put("lock", JSONObject().put("member", d.pub).put("assertion", lock.finish(pending))), null) } catch (_: Exception) { done(null, "failed") }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) = done(null, "cancelled")
        })
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel").build(),
            BiometricPrompt.CryptoObject(pending.signature))
    }

    /** Approve held event `id` of membership `slot` with the lock (review 20 M4): the prompt, then the signing, then
     *  `done` with the signed event, or null and why ("no_lock": lockless, start a hold instead). From an activity in
     *  the signer process only. */
    fun approveHeld(a: FragmentActivity, slot: String, id: String, title: String, subtitle: String, done: (JSONObject?, String?) -> Unit) {
        Proc.signerOnly("LockPrompt.approveHeld")
        val s = Memberships.signer(slot); val d = s.device ?: return done(null, "no_membership")
        val lock = s.lock() ?: return done(null, "no_lock")
        approveSign(a, d, lock, id, title, subtitle) { approval, why ->
            if (approval == null) return@approveSign done(null, why)
            Thread { try { done(d.nip46.approveHeld(id, approval), null) } catch (e: keykin.KeykinException) { done(null, e.code) } catch (_: Exception) { done(null, "failed") } }.apply { isDaemon = true }.start()
        }
    }
}

/** What only the person allows for a NIP-46 site, on a screen the app draws in the signer process: the messages,
 *  private-data and wallet scopes (the main process may allow only sign-in, post and lists, KeykinService.APP_SCOPES). */
object Nip46Asks {
    fun allow(slot: String, signer: String, scope: String) {
        Proc.signerOnly("Nip46Asks.allow")
        Memberships.signer(slot).device?.nip46?.allowScope(signer, scope) ?: throw keykin.KeykinException("no_membership")
    }
}
