package cc.aaro.cosign

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.ui.CosignTheme
import cc.aaro.cosign.ui.Vault
import java.net.URLDecoder
import java.util.concurrent.Executors

/**
 * Android signer, when you need to say something (NIP-55's Intents): an app that isn't
 * connected yet, something destructive, or the first time an app wants your messages.
 * It opens over the app, asks once, answers, and closes. Everything else an app asks
 * goes to Nip55Provider and never opens this.
 */
class Nip55Activity : ComponentActivity() {
    private sealed interface Stage {
        data object Connect : Stage
        data object Dms : Stage
        data class Approve(val what: String) : Stage
        data class Working(val text: String) : Stage
        data class Failed(val text: String) : Stage
    }

    /** The key this app connected to, or (to connect one) the key on screen. */
    private val phone get() = CosignApp.instance.accounts.let { a -> a.forApp(pkg) ?: a.active }
    private val work = Executors.newSingleThreadExecutor()
    private val stage = mutableStateOf<Stage>(Stage.Working("…"))
    private lateinit var type: String
    private lateinit var payload: String
    private var peer = ""
    private var reqId: String? = null
    private var pkg = ""
    private var label = "This app"
    private var event: Event? = null
    /** A web page's request (NIP-55 for the web): the answer goes back to this URL, not to an app. */
    private var callback: String? = null
    private var returnType = "signature"
    private var gzip = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { CosignTheme { Sheet(stage.value) } }
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
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
            if (web == null) return fail("That page's return address isn't one Cosign answers (it must be https).")
            pkg = "web:$web"; label = android.net.Uri.parse(web).host ?: web
        } else {
            pkg = callingActivity?.packageName ?: callingPackage ?: ""
            label = try { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg.ifEmpty { "This app" } }
        }
        when {
            phone.ui.value.member == null -> stage.value = Stage.Failed("Cosign isn't set up yet. Open Cosign and add this phone to your key first.")
            pkg.isEmpty() -> stage.value = Stage.Failed("Open this from an app: Cosign can't tell who's asking.")
            phone.appGrant(pkg) == null -> stage.value = Stage.Connect
            else -> next()
        }
    }

    /** With the app connected: answer, or ask you first. */
    private fun next() {
        val g = phone.appGrant(pkg) ?: return run { stage.value = Stage.Connect }
        when (type) {
            "get_public_key" -> answer("result" to phone.ui.value.member!!.group.groupX)
            "sign_event" -> {
                val ev = try { phone.appEvent(payload) } catch (e: Exception) { return fail("That isn't an event Cosign can sign (${e.message}).") }
                event = ev
                cc.aaro.cosign.core.Policy.refuse(ev)?.let { return fail("Cosign won't sign this: $it.") }
                val hold = phone.holdFor(ev)
                if (hold != null) stage.value = Stage.Approve(hold) else sign(ev, approved = false)
            }
            "nip44_encrypt", "nip44_decrypt", "nip04_encrypt", "nip04_decrypt" ->
                if (!g.dm) stage.value = Stage.Dms else crypt()
            else -> fail("Cosign doesn't do “$type” yet.")
        }
    }

    private fun sign(ev: Event, approved: Boolean) {
        stage.value = Stage.Working(if (approved) "Signing…" else "Signing with your server…")
        work.execute {
            try {
                val signed = phone.signForApp(phone.appGrant(pkg)!!, ev, approved)
                runOnUiThread { answer("result" to signed.sig, "event" to signed.toJson()) }
            } catch (e: NeedsApproval) {
                runOnUiThread { stage.value = Stage.Approve(e.what) } // your server saw what this phone missed
            } catch (_: Revoked) {
                runOnUiThread { stage.value = Stage.Connect }
            } catch (e: Exception) {
                runOnUiThread { fail(e.message ?: "Couldn't sign.") }
            }
        }
    }

    private fun crypt() {
        stage.value = Stage.Working("Working with your server…")
        work.execute {
            try {
                val g = phone.appGrant(pkg)!!
                val encrypt = type.endsWith("encrypt")
                val out = if (type.startsWith("nip44")) phone.nip44(g, peer, payload, encrypt) else phone.nip04(g, peer, payload, encrypt)
                runOnUiThread { answer("result" to out) }
            } catch (e: Exception) {
                runOnUiThread { fail(e.message ?: "Couldn't do that.") }
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
            startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url + android.net.Uri.encode(value))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            finish()
            return
        }
        val data = Intent().putExtra("package", packageName)
        reqId?.let { data.putExtra("id", it) }
        for ((k, v) in extras) data.putExtra(k, v)
        setResult(Activity.RESULT_OK, data)
        finish()
    }

    private fun reject() {
        setResult(Activity.RESULT_OK, Intent().putExtra("rejected", true).apply { reqId?.let { putExtra("id", it) } })
        finish()
    }

    private fun fail(text: String) { stage.value = Stage.Failed(text) }

    /** With several keys on this phone: which one this is about. */
    private fun whichKey() = if (CosignApp.instance.accounts.all.count { it.isMember } > 1) ", as ${phone.label}" else ""

    @Composable
    private fun Sheet(s: Stage) {
        BackHandler { reject() }
        Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
            Column(
                Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                    .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
            ) {
                when (s) {
                    Stage.Connect -> Ask(
                        "Let $label sign as you?" + (if (CosignApp.instance.accounts.all.count { it.isMember } > 1) " (${phone.label})" else ""),
                        "It gets its own access, through your servers — not your key. Everyday things sign automatically; anything destructive comes to this phone first.",
                        "Remove it in Cosign any time.",
                        no = "Don't connect", yes = "Connect $label",
                    ) { phone.connectApp(pkg, label); next() }
                    Stage.Dms -> Ask(
                        "Let $label read and send your messages?",
                        "It asked to encrypt or decrypt a message. Allow it once and it can do that from now on, until you remove it.",
                        null, no = "Not now", yes = "Allow",
                    ) { phone.allowDms(phone.appGrant(pkg)!!); crypt() }
                    is Stage.Approve -> Ask(
                        "Approve?", s.what, "$label asked${whichKey()}. This can't be signed without you.",
                        no = "Deny", yes = "Approve", amber = true,
                    ) { sign(event!!, approved = true) }
                    is Stage.Working -> {
                        CircularProgressIndicator(color = Vault.Teal, modifier = Modifier.align(Alignment.CenterHorizontally))
                        Spacer(Modifier.height(14.dp))
                        Text(s.text, color = Vault.Muted, modifier = Modifier.align(Alignment.CenterHorizontally))
                    }
                    is Stage.Failed -> {
                        Text("Couldn't do that", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                        Spacer(Modifier.height(10.dp))
                        Text(s.text, style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                        Spacer(Modifier.height(20.dp))
                        OutlinedButton({ reject() }, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Close", color = Vault.Text) }
                    }
                }
            }
        }
    }

    @Composable
    private fun Ask(title: String, body: String, small: String?, no: String, yes: String, amber: Boolean = false, onYes: () -> Unit) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = if (amber) Vault.Amber else Vault.Text)
        Spacer(Modifier.height(10.dp))
        Text(body, style = if (amber) MaterialTheme.typography.titleMedium else MaterialTheme.typography.bodyMedium, color = if (amber) Vault.Text else Vault.Muted)
        small?.let { Spacer(Modifier.height(6.dp)); Text(it, style = MaterialTheme.typography.bodySmall, color = Vault.Muted) }
        Spacer(Modifier.height(20.dp))
        // Declining is never the weaker control; the affirmative one says what it does.
        OutlinedButton({ reject() }, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text(no, color = Vault.Text) }
        Spacer(Modifier.height(10.dp))
        Button(onYes, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(if (amber) Vault.Amber else Vault.Teal, Vault.Ground)) {
            Text(yes, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}
