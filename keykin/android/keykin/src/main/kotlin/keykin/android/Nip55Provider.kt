// The Android signer in the background (NIP-55's content resolver), in the signer process: apps the person
// granted ask here and get an answer without the app opening, for what the grant covers (connecting, the kinds
// the person allowed, messages), at most 60 signatures an hour per app. Everything else answers null, and the
// asking app opens the `nostrsigner:` activity (Nip55Request) instead. The same Doors guards as a site's.
package keykin.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import keykin.Doors

class Nip55Provider : ContentProvider() {
    private val signed = HashMap<String, ArrayDeque<Long>>()
    override fun onCreate(): Boolean { Memberships.init(context!!); return true }
    @Synchronized private fun budget(app: String): Boolean {
        val now = System.currentTimeMillis() / 1000; val q = signed.getOrPut(app) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > 3600) q.removeFirst()
        if (q.size >= 60) return false
        q.addLast(now); return true
    }

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val type = uri.authority?.substringAfterLast('.') ?: return null
        // NIP-55 puts [payload, pubkey, current_user] in the projection; some apps use selectionArgs.
        val args = projection?.takeIf { it.isNotEmpty() } ?: selectionArgs ?: return null
        val pkg = callingPackage ?: return null
        val current = args.getOrNull(2)
        return try {
            val grant = Memberships.grantFor(pkg, current) ?: return null
            val d = Memberships.signer(grant.slot).device ?: return null
            if (!current.isNullOrBlank() && current != d.g) return null
            val payload = args.getOrNull(0) ?: ""
            val peer = args.getOrNull(1) ?: ""
            when (type) {
                "GET_PUBLIC_KEY" -> row("result" to d.g)
                "SIGN_EVENT" -> {
                    if (Nip55.kindOf(payload) !in grant.kinds || !budget(grant.app)) return null
                    Nip55.sign(d, payload).let { row("result" to it.getString("sig"), "signature" to it.getString("sig"), "event" to it.toString()) }
                }
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
