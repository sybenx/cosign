// The memberships on this phone, by slot, in the signer process: one KeykinSigner each, the relays each was
// joined over, why one couldn't be opened, and the apps each has granted (NIP-55). KeykinService, Nip55Provider
// and the NIP-55 screen share it. Grants are kept here, by package, signing-certificate digest and install
// (Doors §3.2), scoped: connecting, the event kinds the person allowed, and messages (review 15 M1); as Doors §1
// says, they become to-self encrypted events synced between devices once Doors' grant store is built.
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
    /** The slot's membership, opened from its sealed state on first use; a failure is kept, and shown. */
    @Synchronized fun signer(slot: String): KeykinSigner {
        checkSlot(slot)
        return signers.getOrPut(slot) {
            KeykinSigner(app, slot).also { s ->
                s.onRemoved = { synchronized(this) { failed[slot] = "removed" } }
                relays(slot)?.let { r -> try { s.open(r) } catch (e: KeykinException) { failed[slot] = e.code } catch (_: Exception) { failed[slot] = "open_failed" } }
            }
        }
    }
    @Synchronized fun joined(slot: String) { failed.remove(slot) }
    @Synchronized fun forget(slot: String) {
        checkSlot(slot)
        (signers.remove(slot) ?: KeykinSigner(app, slot)).forget()
        failed.remove(slot)
        store.update { d ->
            d.put("slots", JSONArray(slots() - slot)); d.optJSONObject("relays")?.remove(slot)
            d.optJSONObject("grants")?.let { g -> for (k in g.keys().asSequence().toList()) if (k.startsWith("$slot|")) g.remove(k) }
        }
    }

    // --- NIP-55 grants -------------------------------------------------------------------------------
    /** An app's identity: its package, the SHA-256 of its signing certificates, and when it was installed, so an
     *  impostor under the same name, or the same app uninstalled and installed again, holds no old grant. */
    fun appId(pkg: String): String? = try {
        val info = app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val certs = info.signingInfo?.apkContentsSigners?.map { hex(sha(it.toByteArray())) }?.sorted() ?: return null
        "$pkg:" + hex(sha((certs.joinToString(",") + "@" + info.firstInstallTime).toByteArray()))
    } catch (_: Exception) { null }
    data class Grant(val slot: String, val app: String, val kinds: Set<Int>, val dm: Boolean, val at: Long)
    private fun grantOf(slot: String, id: String, o: JSONObject) = Grant(slot, id, o.optJSONArray("kinds")?.let { a -> (0 until a.length()).map { a.getInt(it) }.toSet() } ?: emptySet(), o.optBoolean("dm"), o.optLong("at"))
    /** Add to `pkg`'s grant in `slot`: connecting always; `kind` to sign silently; `dm` for messages. */
    @Synchronized fun grant(slot: String, pkg: String, kind: Int? = null, dm: Boolean = false): Grant? {
        checkSlot(slot)
        val id = appId(pkg) ?: return null
        var out: Grant? = null
        store.update { d ->
            val gs = d.optJSONObject("grants") ?: JSONObject().also { d.put("grants", it) }
            val o = gs.optJSONObject("$slot|$id") ?: JSONObject().put("kinds", JSONArray()).put("dm", false)
            if (kind != null && (0 until o.getJSONArray("kinds").length()).none { o.getJSONArray("kinds").getInt(it) == kind }) o.getJSONArray("kinds").put(kind)
            if (dm) o.put("dm", true)
            o.put("at", System.currentTimeMillis() / 1000)
            gs.put("$slot|$id", o); out = grantOf(slot, id, o)
        }
        return out
    }
    /** The grant `pkg` holds now: in the slot whose account is `current` when it names one, else the first. */
    @Synchronized fun grantFor(pkg: String, current: String? = null): Grant? {
        val id = appId(pkg) ?: return null
        val gs = store.get().optJSONObject("grants") ?: return null
        for (s in slots()) {
            val o = gs.optJSONObject("$s|$id") ?: continue
            if (!current.isNullOrBlank() && signer(s).device?.g != current) continue
            return grantOf(s, id, o)
        }
        return null
    }
    @Synchronized fun revoke(slot: String, pkg: String) { appId(pkg)?.let { id -> store.update { it.optJSONObject("grants")?.remove("$slot|$id") } } }
    /** The slot whose account is `current` (NIP-55's current_user), or the first. */
    @Synchronized fun slotFor(current: String?): String? = slots().firstOrNull { current.isNullOrBlank() || signer(it).device?.g == current }
}
