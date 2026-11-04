// The memberships on this phone, by slot, in the signer process: one KeykinSigner each, the relays each was
// joined over, and the apps each has granted (NIP-55). KeykinService and Nip55Provider share it. Grants are
// kept here, by package and signing-certificate digest (Doors §3.2); as Doors §1 says, they become to-self
// encrypted events synced between devices once Doors' grant store is built.
package keykin.android

import android.content.Context
import android.content.pm.PackageManager
import keykin.hex
import keykin.sha
import org.json.JSONObject

object Memberships {
    private lateinit var app: Context
    private val prefs by lazy { app.getSharedPreferences("keykin-slots", Context.MODE_PRIVATE) }
    private val grants by lazy { app.getSharedPreferences("keykin-grants", Context.MODE_PRIVATE) }
    private val signers = HashMap<String, KeykinSigner>()
    @Synchronized fun init(context: Context) { Proc.signerOnly("Memberships"); if (!::app.isInitialized) app = context.applicationContext }

    @Synchronized fun slots(): List<String> = prefs.getString("slots", "")!!.split(",").filter { it.isNotBlank() }
    @Synchronized fun addSlot(): String = ("s" + System.currentTimeMillis().toString(36)).also { prefs.edit().putString("slots", (slots() + it).joinToString(",")).apply() }
    @Synchronized fun relays(slot: String): List<String>? = prefs.getString("relays:$slot", null)?.split(",")?.filter { it.isNotBlank() }
    @Synchronized fun setRelays(slot: String, rs: List<String>) = prefs.edit().putString("relays:$slot", rs.joinToString(",")).apply()
    /** The slot's membership, opened from its sealed state on first use. */
    @Synchronized fun signer(slot: String): KeykinSigner = signers.getOrPut(slot) { KeykinSigner(app, slot).also { s -> relays(slot)?.let { r -> try { s.open(r) } catch (_: Exception) {} } } }
    @Synchronized fun forget(slot: String) {
        (signers.remove(slot) ?: KeykinSigner(app, slot)).forget()
        prefs.edit().remove("relays:$slot").putString("slots", (slots() - slot).joinToString(",")).apply()
        val e = grants.edit(); for (k in grants.all.keys.filter { it.startsWith("$slot|") }) e.remove(k); e.apply()
    }

    // --- NIP-55 grants -------------------------------------------------------------------------------
    /** An app's identity: its package and the SHA-256 of its signing certificates, so a reinstalled impostor
     *  under the same package name is a different app. */
    fun appId(pkg: String): String? = try {
        val info = app.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val certs = info.signingInfo?.apkContentsSigners?.map { hex(sha(it.toByteArray())) }?.sorted() ?: return null
        "$pkg:" + hex(sha(certs.joinToString(",").toByteArray()))
    } catch (_: Exception) { null }
    data class Grant(val slot: String, val app: String, val dm: Boolean, val at: Long)
    @Synchronized fun grant(slot: String, pkg: String, dm: Boolean): Grant? {
        val id = appId(pkg) ?: return null
        grants.edit().putString("$slot|$id", JSONObject().put("dm", dm).put("at", System.currentTimeMillis() / 1000).toString()).apply()
        return Grant(slot, id, dm, System.currentTimeMillis() / 1000)
    }
    /** The grant `pkg` holds now, in `slot` or (none named) in any slot; a revoke wins, as it is a removal. */
    @Synchronized fun grantFor(pkg: String, slot: String? = null): Grant? {
        val id = appId(pkg) ?: return null
        for (s in if (slot != null) listOf(slot) else slots()) {
            val g = grants.getString("$s|$id", null) ?: continue
            val o = JSONObject(g); return Grant(s, id, o.optBoolean("dm"), o.optLong("at"))
        }
        return null
    }
    @Synchronized fun revoke(slot: String, pkg: String) { appId(pkg)?.let { grants.edit().remove("$slot|$it").apply() } }
}
