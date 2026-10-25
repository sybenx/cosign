package cc.aaro.cosign

/**
 * Which of the app's two processes this is. The signer (":signer") holds the shares and
 * signs: Secrets, FROST, the member logic in [Signer], the relays your servers use, the
 * always-on service, NIP-55 and site sign-in. The main process draws everything else,
 * including what strangers post (pictures, videos, translations), and only ever asks the
 * signer through [ISigner]; it never sees a share. AndroidManifest.xml puts each piece in its process.
 */
object Proc {
    /** Null on a desktop JVM (unit tests), where there's only one. */
    val name: String? by lazy { try { android.app.Application.getProcessName() } catch (_: Throwable) { null } }
    val isSigner get() = name?.endsWith(":signer") == true

    /** Key material is only ever loaded in the signer process. Throws anywhere else (but not in unit tests). */
    fun signerOnly(what: String) { check(name == null || isSigner) { "$what outside the signer process ($name)" } }
}
