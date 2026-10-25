package cc.aaro.cosign

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri

/**
 * Android signer, in the background (NIP-55's Content Resolver): apps you've connected
 * ask here and get an answer without Cosign opening. Everyday signing answers at once.
 * Anything that needs you (an app not connected yet, something destructive, the first
 * time an app wants your messages) answers null, and the app opens Nip55Activity instead.
 */
class Nip55Provider : ContentProvider() {
    override fun onCreate() = true

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val type = uri.authority?.substringAfterLast('.') ?: return null
        // NIP-55 puts [payload, pubkey, current_user] in the projection; some apps use selectionArgs.
        val args = projection?.takeIf { it.isNotEmpty() } ?: selectionArgs ?: return null
        val current = args.getOrNull(2)
        // The key this app connected to: the one it names, if it does, else the one holding its grant.
        val accounts = CosignApp.instance.signers
        val pkg = callingPackage ?: return null
        val phone = accounts.all.firstOrNull { it.ui.value.member?.group?.groupX == current && it.appGrant(pkg) != null } ?: accounts.forApp(pkg) ?: return null
        val member = phone.ui.value.member ?: return null
        val grant = phone.appGrant(pkg) ?: return null
        if (!current.isNullOrBlank() && current.length == 64 && current != member.group.groupX) return null
        val payload = args.getOrNull(0) ?: ""
        val peer = args.getOrNull(1) ?: ""
        return try {
            when (type) {
                "GET_PUBLIC_KEY" -> row("result" to member.group.groupX)
                "SIGN_EVENT" -> phone.signForApp(grant, phone.appEvent(payload), approved = false).let { row("result" to it.sig, "signature" to it.sig, "event" to it.toJson()) }
                "NIP44_ENCRYPT", "NIP44_DECRYPT", "NIP04_ENCRYPT", "NIP04_DECRYPT" -> {
                    if (!grant.dm) return null
                    val encrypt = type.endsWith("ENCRYPT")
                    row("result" to if (type.startsWith("NIP44")) phone.nip44(grant, peer, payload, encrypt) else phone.nip04(grant, peer, payload, encrypt))
                }
                else -> null
            }
        } catch (_: Exception) {
            null // NeedsApproval, a removed app, or servers out of reach: the app opens Cosign, which says which
        }
    }

    private fun row(vararg cols: Pair<String, String>) = MatrixCursor(cols.map { it.first }.toTypedArray()).apply { addRow(cols.map { it.second }.toTypedArray()) }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?) = 0
}
