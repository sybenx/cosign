// NIP-55 for an activity the app draws in the signer process (`nostrsigner:` intents): what is asked, by which
// app, and the answer once the person decided. The library draws nothing; the app shows `Request.describe()`
// and its buttons, then calls `approve` or `deny`. An approval does what was asked once; only `remember` makes
// it silent next time, and only for the scope it needed (Doors §1), recorded in the synced grant store.
package keykin.android

import android.app.Activity
import android.content.Intent
import keykin.Device
import keykin.Doors
import keykin.Grants
import keykin.Json
import keykin.KeykinException
import org.json.JSONArray
import org.json.JSONObject

object Nip55 {
    /** Sign an app's or site's event (NIP-01 JSON; its id, pubkey and sig ignored), read strictly (§9.5: no
     *  duplicate keys, typed fields), with the Doors guard. */
    fun sign(d: Device, eventJson: String): JSONObject {
        val e = Json.obj(eventJson)
        val kind = (e.opt("kind") as? Number)?.toInt()?.takeIf { it in 0..65535 } ?: throw KeykinException("malformed", "kind")
        val content = e.opt("content") as? String ?: throw KeykinException("malformed", "content")
        val ta = e.opt("tags") ?: JSONArray()
        if (ta !is JSONArray) throw KeykinException("malformed", "tags")
        val tags = (0 until ta.length()).map { i -> (ta.get(i) as? JSONArray ?: throw KeykinException("malformed", "tags")).let { t -> (0 until t.length()).map { t.get(it) as? String ?: throw KeykinException("malformed", "tags") } } }
        val at = e.opt("created_at")?.let { (it as? Number)?.toLong() ?: throw KeykinException("malformed", "created_at") } ?: (System.currentTimeMillis() / 1000)
        Doors.siteGuard(d, kind, tags)
        return d.sign(kind, content, tags, at)
    }
    /** The scope a request needed (Doors §1), for remembering it. */
    fun scopeOf(d: Device, r: Request, result: String?): String? = when (r.type) {
        "get_public_key" -> "sign-in"
        "sign_event" -> kindOf(r.payload)?.let { Grants.scopeForEvent(it) }
        "nip44_encrypt", "nip04_encrypt" -> if (r.peer.lowercase() == d.g) "post" else "dms"
        "nip44_decrypt", "nip04_decrypt" -> Grants.scopeForDecrypt(d.g, r.peer, result)
        else -> null
    }
    fun kindOf(payload: String): Int? = try { (Json.obj(payload).opt("kind") as? Number)?.toInt() } catch (_: Exception) { null }

    class Request(val type: String, val payload: String, val peer: String, val id: String?, val caller: String?, val current: String?) {
        /** A sentence for the screen: which app wants what, in the words of the scope it needs (review 16 M10). */
        fun describe(scope: String? = null): String = (caller ?: "An app") + when (type) {
            "get_public_key" -> " wants to connect to your account"
            "sign_event" -> " wants to sign: " + (try { Json.obj(payload).let { "kind ${it.opt("kind")}, " + (it.opt("content") as? String ?: "").take(80) } } catch (_: Exception) { "an event" })
            "nip44_encrypt", "nip04_encrypt" -> if (scope == "post") " wants to save private data to your account" else " wants to send a message as you"
            "nip44_decrypt", "nip04_decrypt" -> when (scope) {
                "lists" -> " wants to read your private lists"
                "wallet" -> " wants to use your ecash wallet"
                "private-data" -> " wants to read your private notes and app data"
                else -> " wants to read your messages"
            }
            else -> " asks for $type"
        }
    }
    /** The scope this request needs, worked out in the signer process before the screen (a to-self decrypt is
     *  decrypted here first, and judged on its evidence), so the screen says what is really asked. */
    fun scopeNeeded(d: Device, r: Request): String? = when (r.type) {
        "nip44_decrypt", "nip04_decrypt" -> try {
            val plain = if (r.type.startsWith("nip44")) d.nip44(r.peer, r.payload, false) else d.nip04(r.peer, r.payload, false)
            Grants.scopeForDecrypt(d.g, r.peer.lowercase(), plain, if (r.type.startsWith("nip44")) r.payload else null, d.evidence, null)
        } catch (_: Exception) { null }
        else -> scopeOf(d, r, null)
    }
    /** The request in a `nostrsigner:` intent, or null. `caller` is the calling package (Activity.callingPackage).
     *  The payload is the URI's text as sent, never decoded or cut at a `#` (review 15 M2). */
    fun parse(i: Intent, caller: String?): Request? {
        if (i.scheme != "nostrsigner") return null
        val type = i.getStringExtra("type") ?: return null
        var payload = i.dataString?.removePrefix("nostrsigner:") ?: ""
        // Some apps percent-encode the whole payload: an encoded JSON object starts %7B.
        if (payload.startsWith("%7B", ignoreCase = true)) payload = java.net.URLDecoder.decode(payload, "UTF-8")
        return Request(type, payload, i.getStringExtra("pubkey") ?: "", i.getStringExtra("id"), caller, i.getStringExtra("current_user"))
    }
    /** The person approved: do it once, answer, and (with `remember`) let the app ask that again silently. Runs off
     *  the main thread; any fault is a denial, never a crash of the signer process. */
    fun approve(a: Activity, r: Request, remember: Boolean = false) {
        try {
            val pkg = r.caller ?: return deny(a, r)
            Memberships.init(a)
            val slot = Memberships.slotFor(r.current) ?: return deny(a, r)
            val d = Memberships.signer(slot).device ?: return deny(a, r)
            if (!r.current.isNullOrBlank() && r.current != d.g) return deny(a, r)
            val out = Intent()
            when (r.type) {
                "get_public_key" -> out.putExtra("result", d.g).putExtra("package", a.packageName)
                "sign_event" -> sign(d, r.payload).let { out.putExtra("result", it.getString("sig")).putExtra("signature", it.getString("sig")).putExtra("event", it.toString()) }
                "nip44_encrypt", "nip44_decrypt" -> out.putExtra("result", d.nip44(r.peer, r.payload, r.type.endsWith("encrypt")))
                "nip04_encrypt", "nip04_decrypt" -> out.putExtra("result", d.nip04(r.peer, r.payload, r.type.endsWith("encrypt")))
                else -> return deny(a, r)
            }
            // The grant only once it worked: connecting always, and with `remember` the scope this needed.
            Memberships.grant(slot, pkg, r.caller ?: pkg, if (remember) listOfNotNull(scopeOf(d, r, out.getStringExtra("result"))) else emptyList())
            r.id?.let { out.putExtra("id", it) }
            a.setResult(Activity.RESULT_OK, out); a.finish()
        } catch (_: Exception) { deny(a, r) }
    }
    /** NIP-55's rejection: `rejected`, and the request's id. */
    fun deny(a: Activity, r: Request? = null) {
        a.setResult(Activity.RESULT_CANCELED, Intent().putExtra("rejected", true).also { i -> r?.id?.let { i.putExtra("id", it) } }); a.finish()
    }
}
