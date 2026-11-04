// The Android signer in the background (NIP-55's content resolver), in the signer process: apps the person
// granted ask here and get an answer without the app opening. Everything else answers null, and the asking
// app opens the `nostrsigner:` activity (Nip55Request) instead: an app not granted, a decryption it wasn't
// granted, anything that needs an approval, or servers out of reach. The same Doors guards as a site's: never
// the account's machinery, never the account's own data.
package keykin.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import keykin.Doors

class Nip55Provider : ContentProvider() {
    override fun onCreate(): Boolean { Memberships.init(context!!); return true }

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val type = uri.authority?.substringAfterLast('.') ?: return null
        // NIP-55 puts [payload, pubkey, current_user] in the projection; some apps use selectionArgs.
        val args = projection?.takeIf { it.isNotEmpty() } ?: selectionArgs ?: return null
        val pkg = callingPackage ?: return null
        val grant = Memberships.grantFor(pkg) ?: return null
        val d = Memberships.signer(grant.slot).device ?: return null
        val current = args.getOrNull(2)
        if (!current.isNullOrBlank() && current != d.g) return null
        val payload = args.getOrNull(0) ?: ""
        val peer = args.getOrNull(1) ?: ""
        return try {
            when (type) {
                "GET_PUBLIC_KEY" -> row("result" to d.g)
                "SIGN_EVENT" -> Nip55.sign(d, payload).let { row("result" to it.getString("sig"), "signature" to it.getString("sig"), "event" to it.toString()) }
                "NIP44_ENCRYPT", "NIP44_DECRYPT", "NIP04_ENCRYPT", "NIP04_DECRYPT" -> {
                    if (!grant.dm) return null
                    Doors.mayDecrypt(d, peer)
                    val encrypt = type.endsWith("ENCRYPT")
                    row("result" to if (type.startsWith("NIP44")) d.nip44(peer, payload, encrypt) else d.nip04(peer, payload, encrypt))
                }
                else -> null
            }
        } catch (_: Exception) { null }   // needs an approval, declined, or out of reach: the app opens the activity
    }
    private fun row(vararg cols: Pair<String, String>) = MatrixCursor(cols.map { it.first }.toTypedArray()).apply { addRow(cols.map { it.second }.toTypedArray()) }
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?) = 0
}
