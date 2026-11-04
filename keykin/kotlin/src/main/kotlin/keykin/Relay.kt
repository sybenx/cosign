// Members over real Nostr relays (core §9) for the Kotlin device: kind 21059 wraps, re-sent until
// answered, the answer matched by the request id. The JDK's own WebSocket, so no extra dependency;
// an Android build may swap in OkHttp behind the same calls.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class RelayNet(private val relays: List<String>, private val env: Envelope = Envelope(), private val timeoutMs: Long = 9000, private val resendMs: Long = 1500) {
    private val socks = ArrayList<WebSocket>()
    private val waiting = ConcurrentHashMap<String, CompletableFuture<JSONObject>>()   // "to:id" → answer
    private val hosted = ConcurrentHashMap<String, ByteArray>()                         // our keys
    private val seen = ConcurrentHashMap.newKeySet<String>()
    private val parts = ConcurrentHashMap<String, Parts.Reassembler>()

    private inner class Listener : WebSocket.Listener {
        private val buf = StringBuilder()
        override fun onText(ws: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
            buf.append(data)
            if (last) { val s = buf.toString(); buf.setLength(0); try { onMessage(s) } catch (_: Exception) {} }
            ws.request(1); return null
        }
    }
    private fun onMessage(text: String) {
        val m = JSONArray(text)
        if (m.optString(0) != "EVENT" || m.length() < 3) return
        val e = m.getJSONObject(2)
        if (!seen.add(e.optString("id"))) return
        val to = e.optJSONArray("tags")?.let { t -> (0 until t.length()).map { t.getJSONArray(it) }.firstOrNull { it.optString(0) == "p" }?.optString(1) } ?: return
        val sk = hosted[to] ?: return
        val o = try { env.unwrap(sk, Json.obj(e.toString())) } catch (_: KeykinException) { return }
        val body = try { synchronized(this) { parts.getOrPut(to) { Parts.Reassembler() }.take(o.from, o.body, now) } } catch (_: KeykinException) { return } ?: return
        // TS answers carry `re` and `__answer` (runtime/relay.ts).
        if (body.has("re") && body.optBoolean("__answer")) waiting.remove("${o.from}:${body.getString("re")}")?.complete(body.also { it.remove("__answer") })
    }

    fun connect(): RelayNet {
        val client = HttpClient.newHttpClient()
        for (r in relays) socks += client.newWebSocketBuilder().buildAsync(URI(r), Listener()).get(10, TimeUnit.SECONDS)
        return this
    }
    /** Receive what is addressed to this key. */
    fun host(sk: ByteArray, pub: String) {
        hosted[pub] = sk
        val req = JSONArray(listOf("REQ", "kk-${pub.take(12)}", JSONObject().put("kinds", JSONArray(listOf(21059))).put("#p", JSONArray(listOf(pub))).put("since", System.currentTimeMillis() / 1000 - 5))).toString()
        for (s in socks) s.sendText(req, true).get(5, TimeUnit.SECONDS)
    }
    private fun publish(w: JSONObject) { val msg = JSONArray(listOf("EVENT", w)).toString(); for (s in socks) try { s.sendText(msg, true).get(5, TimeUnit.SECONDS) } catch (_: Exception) {} }
    val now: Long get() = System.currentTimeMillis() / 1000

    /** Send `body` from `sk` to `to` and wait for its answer, re-sending until answered or timed out. */
    fun send(sk: ByteArray, to: String, body: JSONObject): JSONObject {
        val id = body.optString("id").ifEmpty { hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }).also { body.put("id", it) } }
        val f = CompletableFuture<JSONObject>()
        waiting["$to:$id"] = f
        val start = System.currentTimeMillis()
        while (!f.isDone && System.currentTimeMillis() - start < timeoutMs) {
            for (part in Parts.split(body)) publish(env.wrap(sk, to, part, now))
            try { return f.get(resendMs, TimeUnit.MILLISECONDS) } catch (_: java.util.concurrent.TimeoutException) {}
        }
        waiting.remove("$to:$id")
        return if (f.isDone) f.get() else JSONObject().put("type", "error").put("code", "unreachable")
    }
    fun close() { for (s in socks) try { s.sendClose(WebSocket.NORMAL_CLOSURE, "").get(2, TimeUnit.SECONDS) } catch (_: Exception) {} }
}
