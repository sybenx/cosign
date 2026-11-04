// Which process this is (as Cosign's Proc): key material lives only in ":signer", which holds the device, the
// relays its servers use and NIP-55; the app's main process draws everything else and reaches the signer only
// through its service, never seeing a share.
package keykin.android

object Proc {
    /** Null on a desktop JVM (unit tests), where there's only one. */
    val name: String? by lazy { try { android.app.Application.getProcessName() } catch (_: Throwable) { null } }
    val isSigner get() = name?.endsWith(":signer") == true
    /** Throws anywhere but the signer process (and never in unit tests). */
    fun signerOnly(what: String) { check(name == null || isSigner) { "$what outside the signer process ($name)" } }
}
