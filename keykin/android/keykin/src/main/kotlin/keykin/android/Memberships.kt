// The memberships on this phone, by slot, in the signer process: one KeykinSigner each, the relays each was
// joined over, why one couldn't be opened, and the apps each has granted (NIP-55). KeykinService, Nip55Provider
// and the NIP-55 screen share it. NIP-55 grants are entries in each membership's grant store (Doors §1–§2): by
// package and signing-certificate digest, on this install, with Doors' scopes, synced so every device lists them.
package keykin.android

import android.content.Context
import android.content.pm.PackageManager
import keykin.KeykinException
import keykin.hex
import keykin.sha
import org.json.JSONArray
import org.json.JSONObject

object Memberships {
    private lateinit var app: Context
    private val store by lazy { NoBackup(app, "memberships") }
    private val signers = HashMap<String, KeykinSigner>()
    /** Why a slot's sealed membership couldn't be opened (it is never overwritten by a join: review 15 M4). */
    private val failed = HashMap<String, String>()
    private val SLOT = Regex("^[a-z0-9]{1,32}$")
    @Synchronized fun init(context: Context) { Proc.signerOnly("Memberships"); if (!::app.isInitialized) app = context.applicationContext }

    @Synchronized fun slots(): List<String> = store.get().optJSONArray("slots")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
    @Synchronized fun addSlot(): String {
        val slot = "s" + System.currentTimeMillis().toString(36)
        store.update { it.put("slots", JSONArray(slots() + slot)) }
        return slot
    }
    fun checkSlot(slot: String) { if (!SLOT.matches(slot)) throw KeykinException("bad_slot") }
    @Synchronized fun relays(slot: String): List<String>? = store.get().optJSONObject("relays")?.optJSONArray(slot)?.let { a -> (0 until a.length()).map { a.getString(it) } }
    @Synchronized fun setRelays(slot: String, rs: List<String>) = store.update { it.put("relays", (it.optJSONObject("relays") ?: JSONObject()).put(slot, JSONArray(rs))) }
    @Synchronized fun openError(slot: String): String? = failed[slot]
    /** Whether the slot's membership has been opened in this process yet (opening reads storage and reaches the relays).
     *  Not under this object's lock, which an opening holds for seconds. */
    fun isOpen(slot: String): Boolean = slot in opened
    private val opened = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    /** The slot's membership, opened from its sealed state on first use; a failure is kept, and shown. */
    @Synchronized fun signer(slot: String): KeykinSigner {
        checkSlot(slot)
        return signers.getOrPut(slot) {
            KeykinSigner(app, slot).also { s ->
                s.onRemoved = { synchronized(this) { failed[slot] = "removed" } }
                relays(slot)?.let { r -> try { s.open(r) } catch (e: KeykinException) { failed[slot] = e.code } catch (_: Exception) { failed[slot] = "open_failed" } }
                opened += slot
            }
        }
    }
    @Synchronized fun joined(slot: String) { failed.remove(slot) }
    @Synchronized fun forget(slot: String) {
        checkSlot(slot)
        (signers.remove(slot) ?: KeykinSigner(app, slot)).forget()
        failed.remove(slot); opened -= slot
        store.update { d ->
            d.put("slots", JSONArray(slots() - slot)); d.optJSONObject("relays")?.remove(slot)
        }
    }

    // --- NIP-55 grants (Doors §1–§2: entries in the membership's grant store, synced between devices) ------
    /** An app's site: its package and the SHA-256 of its signing certificates (Doors §3.2), so an impostor under
     *  the same name is another site; its connection: this install, so a reinstall is a new connection. */
    fun appSite(pkg: String): Pair<String, String>? = try {
        val info = app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val certs = info.signingInfo?.apkContentsSigners?.map { hex(sha(it.toByteArray())) }?.sorted() ?: return null
        ("$pkg:" + hex(sha(certs.joinToString(",").toByteArray()))) to ("install:${info.firstInstallTime}")
    } catch (_: Exception) { null }
    data class Grant(val slot: String, val id: String, val scopes: Set<String>)
    /** The grant `pkg` holds on this connection: in the slot whose account is `current` when it names one. */
    @Synchronized fun grantFor(pkg: String, current: String? = null): Grant? {
        val (site, conn) = appSite(pkg) ?: return null
        for (s in slots()) {
            val d = signer(s).device ?: continue
            if (!current.isNullOrBlank() && d.g != current) continue
            val e = d.grants.forSite(site, "nip55", conn) ?: continue
            return Grant(s, e.getString("id"), d.grants.scopesOf(e))
        }
        return null
    }
    /** A human act on this phone ("Allow *app*"): the app's grant in `slot` gets `scopes` (sign-in always), made or
     *  widened, and published so every device lists it. */
    @Synchronized fun grant(slot: String, pkg: String, says: String, scopes: Collection<String>): Grant? {
        checkSlot(slot)
        val (site, conn) = appSite(pkg) ?: return null
        val d = signer(slot).device ?: return null
        val want = (scopes + "sign-in").toSet()
        val e = d.grants.forSite(site, "nip55", conn)?.let { old -> if (d.grants.scopesOf(old).containsAll(want)) old else d.grants.widen(old.getString("id"), want.toList()) }
            ?: d.grants.make(site, says, "nip55", conn, want.toList())
        // Stored before it is published: a signer process dying in between never loses it (review 16 M6).
        d.publishGrantsSoon()
        return Grant(slot, e.getString("id"), d.grants.scopesOf(e))
    }
    @Synchronized fun revoke(slot: String, pkg: String) {
        val (site, conn) = appSite(pkg) ?: return
        val d = signer(slot).device ?: return
        d.grants.forSite(site, "nip55", conn)?.let { d.grants.end(d.pub, it.getString("id")); d.publishGrantsSoon() }
    }
    /** The slot whose account is `current` (NIP-55's current_user), or the first. */
    @Synchronized fun slotFor(current: String?): String? = slots().firstOrNull { current.isNullOrBlank() || signer(it).device?.g == current }
}
