package cc.aaro.cosign

import android.app.Activity
import android.content.Intent
import cc.aaro.cosign.core.Event
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.URLDecoder
import java.util.concurrent.Executors

/**
 * Android signer, when you need to say something (NIP-55's Intents): an app that isn't
 * connected yet, something destructive, or the first time an app wants your messages.
 * Everything else an app asks goes to Nip55Provider and never opens this.
 *
 * The app's own activity for `nostrsigner:` (in the signer process) hands each intent to
 * [handle], draws [stage], and calls [connect], [allowDms], [approve] or [reject] on the
 * person's answer. This answers the asking app and closes [activity].
 */
class Nip55Request(private val activity: Activity) {
    sealed interface Stage {
        data object Connect : Stage
        data object Dms : Stage
        data class Approve(val what: String) : Stage
        data class Working(val text: String) : Stage
        data class Failed(val text: String) : Stage
    }

    /** The key this app connected to, or (to connect one) the key on screen. */
    val phone get() = Cosign.signers.let { a -> a.forApp(pkg) ?: a.active }
    private val work = Executors.newSingleThreadExecutor()
    private val current = MutableStateFlow<Stage>(Stage.Working("…"))
    val stage: StateFlow<Stage> = current
    private lateinit var type: String
    private lateinit var payload: String
    private var peer = ""
    private var reqId: String? = null
    private var pkg = ""
    /** Who's asking: the app's name, or the page's host. */
    var label = "This app"
        private set
    private var event: Event? = null
    /** A web page's request (NIP-55 for the web): the answer goes back to this URL, not to an app. */
    private var callback: String? = null
    private var returnType = "signature"
    private var gzip = false

    /** More than one key on this phone: say which one this is about. */
    val several get() = Cosign.signers.all.count { it.isMember } > 1

    fun handle(intent: Intent) {
        val data = intent.dataString?.removePrefix("nostrsigner:") ?: ""
        // A web page puts everything in the link: nostrsigner:<payload>?type=…&callbackUrl=…
        val query = data.substringAfter('?', "").split('&').filter { '=' in it }
            .associate { it.substringBefore('=') to URLDecoder.decode(it.substringAfter('='), "UTF-8") }
        callback = query["callbackUrl"]?.takeIf { intent.getStringExtra("type") == null }
        val raw = if (callback != null) data.substringBefore('?') else data
        type = intent.getStringExtra("type") ?: query["type"] ?: "get_public_key"
        payload = if (raw.startsWith("%7B", ignoreCase = true) || (type != "sign_event" && Regex("%[0-9A-Fa-f]{2}").containsMatchIn(raw)))
            URLDecoder.decode(raw, "UTF-8") else raw
        peer = intent.getStringExtra("pubkey") ?: query["pubkey"] ?: ""
        reqId = intent.getStringExtra("id")
        val web = callback?.let { webOrigin(it) }
        if (callback != null) {
            returnType = query["returnType"] ?: "signature"; gzip = query["compressionType"] == "gzip"
            if (web == null) return fail("That page's return address isn't one $appName answers (it must be https).")
            pkg = "web:$web"; label = android.net.Uri.parse(web).host ?: web
        } else {
            val pm = activity.packageManager
            pkg = activity.callingActivity?.packageName ?: activity.callingPackage ?: ""
            label = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg.ifEmpty { "This app" } }
        }
        when {
            phone.ui.value.member == null -> current.value = Stage.Failed("$appName isn't set up yet. Open $appName and set up your account first.")
            pkg.isEmpty() -> current.value = Stage.Failed("Open this from an app: $appName can't tell who's asking.")
            phone.appGrant(pkg) == null -> current.value = Stage.Connect
            else -> next()
        }
    }

    /** Yes to [Stage.Connect]. */
    fun connect() { phone.connectApp(pkg, label); next() }

    /** Yes to [Stage.Dms]. */
    fun allowDms() { phone.allowDms(phone.appGrant(pkg)!!); crypt() }

    /** Yes to [Stage.Approve]. */
    fun approve() = sign(event!!, approved = true)

    /** With the app connected: answer, or ask you first. */
    private fun next() {
        val g = phone.appGrant(pkg) ?: return run { current.value = Stage.Connect }
        when (type) {
            "get_public_key" -> answer("result" to phone.ui.value.member!!.group.groupX)
            "sign_event" -> {
                val ev = try { phone.appEvent(payload) } catch (e: Exception) { return fail("That isn't an event $appName can sign (${e.message}).") }
                event = ev
                cc.aaro.cosign.core.Policy.refuse(ev)?.let { return fail("$appName won't sign this: $it.") }
                val hold = phone.holdFor(ev)
                if (hold != null) current.value = Stage.Approve(hold) else sign(ev, approved = false)
            }
            "nip44_encrypt", "nip44_decrypt", "nip04_encrypt", "nip04_decrypt" ->
                if (!g.dm) current.value = Stage.Dms else crypt()
            else -> fail("$appName doesn't do “$type” yet.")
        }
    }

    private fun sign(ev: Event, approved: Boolean) {
        current.value = Stage.Working(if (approved) "Signing…" else "Signing with your server…")
        // What this request is, as it is now: an app may send another before this one is
        // answered (the sheet is singleTop and takes them on the same object), and work
        // already under way must stay the request it started as.
        val app = pkg
        work.execute {
            try {
                val signed = phone.signForApp(phone.appGrant(app)!!, ev, approved)
                activity.runOnUiThread { answer("result" to signed.sig, "event" to signed.toJson()) }
            } catch (e: NeedsApproval) {
                activity.runOnUiThread { current.value = Stage.Approve(e.what) } // your server saw what this phone missed
            } catch (_: Revoked) {
                activity.runOnUiThread { current.value = Stage.Connect }
            } catch (e: Exception) {
                activity.runOnUiThread { fail(e.message ?: "Couldn't sign.") }
            }
        }
    }

    private fun crypt() {
        current.value = Stage.Working("Working with your server…")
        // The request as it is now, for the same reason as in [sign].
        val app = pkg; val how = type; val who = peer; val what = payload
        work.execute {
            try {
                val g = phone.appGrant(app)!!
                val encrypt = how.endsWith("encrypt")
                val out = if (how.startsWith("nip44")) phone.nip44(g, who, what, encrypt) else phone.nip04(g, who, what, encrypt)
                activity.runOnUiThread { answer("result" to out) }
            } catch (e: Exception) {
                activity.runOnUiThread { fail(e.message ?: "Couldn't do that.") }
            }
        }
    }

    /** The site behind a callback URL: https, or http on this machine for a site being built. */
    private fun webOrigin(url: String): String? {
        val u = android.net.Uri.parse(url)
        val host = u.host ?: return null
        if (u.scheme != "https" && !(u.scheme == "http" && host in setOf("localhost", "127.0.0.1"))) return null
        return "${u.scheme}://$host${if (u.port > 0) ":${u.port}" else ""}"
    }

    private fun answer(vararg extras: Pair<String, String>) {
        callback?.let { url ->
            // The page asked for the whole event or just the result; gzip as "Signer1" + base64.
            val map = extras.toMap()
            var value = (if (returnType == "event") map["event"] else null) ?: map["result"] ?: ""
            if (gzip) value = "Signer1" + java.util.Base64.getEncoder().encodeToString(
                java.io.ByteArrayOutputStream().also { b -> java.util.zip.GZIPOutputStream(b).use { it.write(value.toByteArray()) } }.toByteArray())
            activity.startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url + android.net.Uri.encode(value))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            activity.finish()
            return
        }
        val data = Intent().putExtra("package", activity.packageName)
        reqId?.let { data.putExtra("id", it) }
        for ((k, v) in extras) data.putExtra(k, v)
        activity.setResult(Activity.RESULT_OK, data)
        activity.finish()
    }

    /** No, or back: the asking app hears it was rejected. */
    fun reject() {
        activity.setResult(Activity.RESULT_OK, Intent().putExtra("rejected", true).apply { reqId?.let { putExtra("id", it) } })
        activity.finish()
    }

    private fun fail(text: String) { current.value = Stage.Failed(text) }
}
