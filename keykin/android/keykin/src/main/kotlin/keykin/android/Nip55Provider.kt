// The Android signer in the background (NIP-55's content resolver), in the signer process: apps the person
// granted ask here and get an answer without the app opening, for what the grant's scopes cover (Doors §1:
// sign-in, post, lists, dms, private-data, wallet), at most 60 signatures an hour per app. Everything else answers null, and the
// asking app opens the `nostrsigner:` activity (Nip55Request) instead. The same Doors guards as a site's.
package keykin.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import keykin.Grants

class Nip55Provider : ContentProvider() {
    private val signed = HashMap<String, ArrayDeque<Long>>()
    override fun onCreate(): Boolean { Memberships.init(context!!); return true }
    /** At most `max` an hour per grant and kind of call (signing 60; encrypting and decrypting 300: review 16 M9). */
    @Synchronized private fun budget(key: String, max: Int = 60): Boolean {
        val now = System.currentTimeMillis() / 1000; val q = signed.getOrPut(key) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > 3600) q.removeFirst()
        if (q.size >= max) return false
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
                "GET_PUBLIC_KEY" -> if ("sign-in" in grant.scopes) row("result" to d.g) else null
                "SIGN_EVENT" -> {
                    val kind = Nip55.kindOf(payload) ?: return null
                    if (Grants.scopeForEvent(kind) !in grant.scopes || !budget(grant.id)) return null
                    Nip55.sign(d, payload, "${d.pub}:${grant.id}").let { d.grants.used(grant.id); row("result" to it.getString("sig"), "signature" to it.getString("sig"), "event" to it.toString()) }
                }
                "NIP44_ENCRYPT", "NIP04_ENCRYPT" -> {
                    if ((if (peer.lowercase() == d.g) "post" else "dms") !in grant.scopes || !budget("crypt:${grant.id}", 300)) return null
                    // An encryption to self is this grant's: evidence for its later decrypts (Doors §1).
                    // Doors 20 §2: never a vault invitation or payload encrypted for an app.
                    if (keykin.Doors.vaultPlaintext(payload)) return null
                    row("result" to if (type.startsWith("NIP44")) d.nip44(peer, payload, true, "${d.pub}:${grant.id}") else d.nip04(peer, payload, true))
                }
                "NIP44_DECRYPT", "NIP04_DECRYPT" -> {
                    val toSelf = peer.lowercase() == d.g
                    // Refused before any round when the grant can't hold the answer at all (review 16 M9).
                    if (if (toSelf) grant.scopes.none { it in setOf("lists", "wallet", "private-data", "dms") } else "dms" !in grant.scopes) return null
                    if (!budget("crypt:${grant.id}", 300)) return null
                    val plain = if (type.startsWith("NIP44")) d.nip44(peer, payload, false) else d.nip04(peer, payload, false)
                    // With someone else's key, dms; to the account itself, the scope its evidence and plaintext need.
                    val need = Grants.scopeForDecrypt(d.g, peer.lowercase(), plain, if (type.startsWith("NIP44")) payload else null, d.evidence, "${d.pub}:${grant.id}")
                    if (need !in grant.scopes || keykin.Doors.vaultPlaintext(plain)) return null
                    row("result" to plain)
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
