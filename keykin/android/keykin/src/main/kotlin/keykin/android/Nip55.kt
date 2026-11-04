// NIP-55 for an activity the app draws in the signer process (`nostrsigner:` intents): what is asked, by which
// app, and the answer once the person decided. The library draws nothing; the app shows `Request.describe()`
// and the buttons, then calls `approve` or `deny`.
package keykin.android

import android.app.Activity
import android.content.Intent
import keykin.Device
import keykin.Doors
import keykin.KeykinException
import org.json.JSONArray
import org.json.JSONObject

object Nip55 {
    /** Sign a site's or app's event (NIP-01 JSON, its id, pubkey and sig ignored), with the Doors guard. */
    fun sign(d: Device, eventJson: String): JSONObject {
        val e = JSONObject(eventJson)
        val kind = e.getInt("kind")
        val tags = (e.optJSONArray("tags") ?: JSONArray()).let { a -> (0 until a.length()).map { i -> a.getJSONArray(i).let { t -> (0 until t.length()).map { t.getString(it) } } } }
        Doors.siteGuard(d, kind, tags)
        return d.sign(kind, e.optString("content"), tags, e.optLong("created_at", System.currentTimeMillis() / 1000))
    }

    class Request(val type: String, val payload: String, val peer: String, val id: String?, val caller: String?, val current: String?) {
        /** A sentence for the screen: which app wants what. */
        fun describe(): String = (caller ?: "An app") + when (type) {
            "get_public_key" -> " wants to connect to your account"
            "sign_event" -> " wants to sign: " + (try { JSONObject(payload).let { "kind ${it.getInt("kind")}, " + it.optString("content").take(80) } } catch (_: Exception) { "an event" })
            "nip44_encrypt", "nip04_encrypt" -> " wants to encrypt a message"
            "nip44_decrypt", "nip04_decrypt" -> " wants to read your messages"
            else -> " asks for $type"
        }
    }
    /** The request in a `nostrsigner:` intent, or null. `caller` is the calling package (Activity.callingPackage). */
    fun parse(i: Intent, caller: String?): Request? {
        if (i.scheme != "nostrsigner") return null
        val type = i.getStringExtra("type") ?: return null
        return Request(type, i.data?.schemeSpecificPart ?: "", i.getStringExtra("pubkey") ?: "", i.getStringExtra("id"), caller, i.getStringExtra("current_user"))
    }
    /** The person approved: grant the app (in `slot`; `dm` for messages), do it, and answer. */
    fun approve(a: Activity, r: Request, slot: String, dm: Boolean = false) {
        val pkg = r.caller ?: return deny(a)
        Memberships.init(a)
        Memberships.grant(slot, pkg, dm || r.type.endsWith("decrypt") || r.type.endsWith("encrypt")) ?: return deny(a)
        val d = Memberships.signer(slot).device ?: return deny(a)
        val out = Intent()
        try {
            when (r.type) {
                "get_public_key" -> out.putExtra("result", d.g).putExtra("package", a.packageName)
                "sign_event" -> sign(d, r.payload).let { out.putExtra("result", it.getString("sig")).putExtra("signature", it.getString("sig")).putExtra("event", it.toString()) }
                "nip44_encrypt", "nip44_decrypt" -> { Doors.mayDecrypt(d, r.peer); out.putExtra("result", d.nip44(r.peer, r.payload, r.type.endsWith("encrypt"))) }
                "nip04_encrypt", "nip04_decrypt" -> { Doors.mayDecrypt(d, r.peer); out.putExtra("result", d.nip04(r.peer, r.payload, r.type.endsWith("encrypt"))) }
                else -> return deny(a)
            }
        } catch (_: KeykinException) { return deny(a) }
        r.id?.let { out.putExtra("id", it) }
        a.setResult(Activity.RESULT_OK, out); a.finish()
    }
    fun deny(a: Activity) { a.setResult(Activity.RESULT_CANCELED); a.finish() }
}
