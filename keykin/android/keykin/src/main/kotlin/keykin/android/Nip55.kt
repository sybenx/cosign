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
     *  duplicate keys, typed fields), with the Doors guard. An app's event is judged by Device policy §2 first: in the
     *  background (`screen` false, the content provider) only a Silent one is signed, anything else refused so the app
     *  falls back to the screen; on the screen the person's tap is the Confirm. Held is never signed here. The member
     *  app's own events (`owner` member) are the person's edits and aren't judged. */
    fun sign(d: Device, eventJson: String, owner: String = "member", screen: Boolean = false): JSONObject {
        val (kind, content, tags, at) = read(d, eventJson)
        if (owner != "member") {
            val e = keykin.Unsigned(d.g, at, kind, tags, content)
            // In the background: judged and signed one at a time per app, only what is Silent (review 18 M1).
            if (!screen) {
                val (gate, signed) = d.guard.serve(e, owner, scopesOf(d, owner), wait = false) { d.sign(kind, content, tags, at, owner) }
                if (signed != null) return signed
                throw KeykinException(when { gate.ok == "held" -> "needs_approval"; gate.error?.startsWith("try-later") == true -> "try_later"; gate.error != null -> "declined"; else -> "needs_screen" }, gate.verdict.reason)
            }
            val v = d.judge(e, owner, scopesOf(d, owner))
            when (v.level) {
                "silent" -> {}
                "confirm", "undo" -> d.guard.allowNow(owner, e)
                "held" -> throw KeykinException("needs_approval", v.reason)
                else -> throw KeykinException(if (v.level == "try-later") "try_later" else "declined", v.reason)
            }
        }
        return d.sign(kind, content, tags, at, owner)
    }
    /** What Device policy §2 says of an app's event, for the screen to name (its reason) before the person taps. */
    fun verdict(d: Device, eventJson: String, owner: String): keykin.Verdict? = try {
        val (kind, content, tags, at) = read(d, eventJson); d.judge(keykin.Unsigned(d.g, at, kind, tags, content), owner, scopesOf(d, owner))
    } catch (_: Exception) { null }
    private fun scopesOf(d: Device, owner: String) = d.grants.own[owner.substringAfter(':')]?.let { d.grants.scopesOf(it).toList() } ?: emptyList()
    private data class Read(val kind: Int, val content: String, val tags: List<List<String>>, val at: Long)
    private fun read(d: Device, eventJson: String): Read {
        val e = Json.obj(eventJson)
        val kind = (e.opt("kind") as? Number)?.toInt()?.takeIf { it in 0..65535 } ?: throw KeykinException("malformed", "kind")
        val content = e.opt("content") as? String ?: throw KeykinException("malformed", "content")
        val ta = e.opt("tags") ?: JSONArray()
        if (ta !is JSONArray) throw KeykinException("malformed", "tags")
        val tags = (0 until ta.length()).map { i -> (ta.get(i) as? JSONArray ?: throw KeykinException("malformed", "tags")).let { t -> (0 until t.length()).map { t.get(it) as? String ?: throw KeykinException("malformed", "tags") } } }
        val at = e.opt("created_at")?.let { (it as? Number)?.toLong() ?: throw KeykinException("malformed", "created_at") } ?: (System.currentTimeMillis() / 1000)
        Doors.siteGuard(d, kind, tags)
        return Read(kind, content, tags, at)
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
        /** `reason`: Device policy's words for an event that needs a Confirm (`verdict`), shown with it. */
        fun describe(scope: String? = null, reason: String? = null): String = (caller ?: "An app") + when (type) {
            "get_public_key" -> " wants to connect to your account"
            "sign_event" -> " wants to sign: " + (try { Json.obj(payload).let { "kind ${it.opt("kind")}, " + (it.opt("content") as? String ?: "").take(80) } } catch (_: Exception) { "an event" }) +
                (reason?.let { " ($it)" } ?: "")
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
            // The scope this needs, judged with the evidence, as the screen named it: "Always" stores that, never more
            // (review 17 H1).
            val scope = scopeNeeded(d, r)
            // The app's grant (connecting) first, so what it encrypts or gets signed is recorded as its own (L3).
            val grant = Memberships.grant(slot, pkg, r.caller ?: pkg, emptyList()) ?: return deny(a, r)
            val owner = "${d.pub}:${grant.id}"
            val out = Intent()
            when (r.type) {
                "get_public_key" -> out.putExtra("result", d.g).putExtra("package", a.packageName)
                "sign_event" -> sign(d, r.payload, owner, screen = true).let { out.putExtra("result", it.getString("sig")).putExtra("signature", it.getString("sig")).putExtra("event", it.toString()) }
                // Doors 20 §2: no vault material encrypted for an app, nor released to one, even on the screen.
                "nip44_encrypt", "nip44_decrypt", "nip04_encrypt", "nip04_decrypt" -> {
                    if (r.type.endsWith("encrypt") && keykin.Doors.vaultPlaintext(r.payload)) return deny(a, r)
                    val res = if (r.type.startsWith("nip44")) d.nip44(r.peer, r.payload, r.type.endsWith("encrypt"), owner) else d.nip04(r.peer, r.payload, r.type.endsWith("encrypt"))
                    if (r.type.endsWith("decrypt") && keykin.Doors.vaultPlaintext(res)) return deny(a, r)
                    out.putExtra("result", res)
                }
                else -> return deny(a, r)
            }
            if (remember && scope != null && scope != "malformed") Memberships.grant(slot, pkg, r.caller ?: pkg, listOf(scope))
            r.id?.let { out.putExtra("id", it) }
            a.setResult(Activity.RESULT_OK, out); a.finish()
        } catch (_: Exception) { deny(a, r) }
    }
    /** NIP-55's rejection: `rejected`, and the request's id. */
    fun deny(a: Activity, r: Request? = null) {
        a.setResult(Activity.RESULT_CANCELED, Intent().putExtra("rejected", true).also { i -> r?.id?.let { i.putExtra("id", it) } }); a.finish()
    }
}
