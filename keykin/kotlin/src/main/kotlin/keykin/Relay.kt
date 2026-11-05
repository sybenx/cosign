// Members over real Nostr relays (core §9) for the Kotlin device: kind 21059 wraps, re-sent until
// answered, the answer matched by the request id. The socket is a `Wire`: the JDK's on the JVM
// (JdkWire.kt), OkHttp on Android (keykin-android). A dropped relay is redialled, its subscriptions re-sent.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

private const val ANSWER_TTL_S = 600L
private const val SEEN_MAX = 50_000
/** How far behind ours a sender's clock may be for its live messages still to reach us (judged then by their
 *  lifetime, core §5.6, and replays by the answered cache). */
private const val CLOCK_SLACK_S = 120L

/** A relay socket: text frames in and out. */
interface WireSocket { fun send(text: String): Boolean; fun close() }
interface Wire { fun open(url: String, onText: (String) -> Unit, onClosed: () -> Unit): WireSocket }

class RelayNet(private val relays: List<String>, private val env: Envelope = Envelope(), private val timeoutMs: Long = 9000, private val resendMs: Long = 1500,
               private val wire: Wire? = null) {
    /** One per relay, redialled when it drops; `subs` are re-sent on every dial. */
    private inner class Conn(val url: String) {
        @Volatile var sock: WireSocket? = null
        @Volatile var closed = false
        private var backoff = 1000L
        fun dial() {
            if (closed) return
            sock = try { (wire ?: Keykin.wire ?: refuse("no_wire", "set Keykin.wire")).open(url, { t -> try { onMessage(t, url) } catch (_: Exception) {} }, { dropped() }) } catch (e: KeykinException) { throw e } catch (_: Exception) { null }
            if (sock == null) { dropped(); return }
            backoff = 1000L
            for (f in subs.values) sock?.send(f())
        }
        fun dropped() {
            sock = null
            if (closed) return
            val wait = backoff; backoff = minOf(backoff * 2, 30_000L)
            redial.schedule({ dial() }, wait, java.util.concurrent.TimeUnit.MILLISECONDS)
        }
        fun send(text: String) { sock?.send(text) }
    }
    private val conns = ArrayList<Conn>()
    /** Subscriptions by id, as a REQ to send (made fresh at each dial, so `since` stays recent). */
    private val subs = ConcurrentHashMap<String, () -> String>()
    private val redial = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "keykin-relay-redial").also { it.isDaemon = true } }
    private val waiting = ConcurrentHashMap<String, CompletableFuture<JSONObject>>()   // "to:id" → answer
    private val hosted = ConcurrentHashMap<String, ByteArray>()                         // our keys
    /** What answers requests sent to one of our keys (null: answers, or ignores, nothing). */
    private val handlers = ConcurrentHashMap<String, (String, JSONObject, Long) -> JSONObject?>()
    // Answers kept 10 minutes for re-sends, as TS does; event ids remembered up to a bound (review 12 L2).
    private val answered = ConcurrentHashMap<String, Pair<Long, JSONObject>>()
    @Volatile private var pruned = 0L
    private val handlerPool = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-relay-handlers").also { it.isDaemon = true } }
    private val seen: MutableSet<String> = java.util.Collections.synchronizedSet(java.util.Collections.newSetFromMap(object : LinkedHashMap<String, Boolean>() {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, Boolean>?) = size > SEEN_MAX
    }))
    private val parts = ConcurrentHashMap<String, Parts.Reassembler>()

    /** Raw-event subscriptions (Doors §3.3), by subscription id, each with its own seen set. */
    private val watches = ConcurrentHashMap<String, Pair<(JSONObject) -> Unit, MutableSet<String>>>()
    /** One-shot queries by subscription id: what came, and how many relays haven't said EOSE yet. */
    private val queries = ConcurrentHashMap<String, Pair<MutableList<JSONObject>, java.util.concurrent.CountDownLatch>>()
    /** The stored events matching `filter`, from every relay, until each says EOSE (or `timeoutMs`). */
    /** As `queryCounted`, the events only. */
    fun query(filter: JSONObject, timeoutMs: Long = 4000): List<Event> = queryCounted(filter, timeoutMs).first
    /** The stored events matching `filter`, at most 5,000, and how many relays answered of how many were asked. */
    fun queryCounted(filter: JSONObject, timeoutMs: Long = 4000): Triple<List<Event>, Int, Int> {
        val id = "kq-" + hex(ByteArray(6).also { java.security.SecureRandom().nextBytes(it) })
        val got = java.util.Collections.synchronizedList(ArrayList<JSONObject>())
        val asked = conns.count { it.sock != null }
        val latch = java.util.concurrent.CountDownLatch(asked)
        queries[id] = got to latch
        sendAll(JSONArray(listOf("REQ", id, filter)).toString())
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        val answered = asked - latch.count.toInt()
        queries.remove(id); sendAll(JSONArray(listOf("CLOSE", id)).toString())
        // One malformed event from any relay costs only itself (review 16 M7).
        val evs = synchronized(got) { got.toList() }.mapNotNull { try { Event.of(it).takeIf(::verifyEvent) } catch (_: Exception) { null } }.distinctBy { it.id }
        return Triple(evs, answered, asked)
    }
    private fun onMessage(text: String, url: String = "") {
        val m = JSONArray(text)
        // Doors §2's per-relay answers: an OK for a publish, an EOSE (never a CLOSED or a NOTICE) for a fetch.
        if (m.optString(0) == "OK") { okWaits.remove("$url ${m.optString(1)}")?.complete(if (m.optBoolean(2)) true else m.optString(3)); return }
        if (m.optString(0) == "EOSE") eachWaits["$url ${m.optString(1)}"]?.let { it.countDown() }
        if (m.optString(0) == "EOSE") { queries[m.optString(1)]?.second?.countDown(); return }
        if (m.optString(0) == "EVENT" && m.length() >= 3) queries[m.optString(1)]?.let { (got, _) -> (m.opt(2) as? JSONObject)?.let { if (got.size < 5000) got += it }; return }
        if (m.optString(0) != "EVENT" || m.length() < 3) return
        val e = m.getJSONObject(2)
        watches[m.optString(1)]?.let { (cb, seenHere) ->
            if (seenHere.add(e.optString("id"))) try { if (verifyEvent(Event.of(Json.obj(e.toString())))) cb(e) } catch (_: Exception) {}
            return
        }
        if (!seen.add(e.optString("id"))) return
        val to = e.optJSONArray("tags")?.let { t -> (0 until t.length()).map { t.getJSONArray(it) }.firstOrNull { it.optString(0) == "p" }?.optString(1) } ?: return
        val sk = hosted[to] ?: return
        val o = try { env.unwrap(sk, Json.obj(e.toString())) } catch (_: KeykinException) { return }
        val body = try { synchronized(this) { parts.getOrPut(to) { Parts.Reassembler() }.take(o.from, o.body, now) } } catch (_: KeykinException) { return } ?: return
        // TS answers carry `re` and `__answer` (runtime/relay.ts).
        if (body.has("re") && body.optBoolean("__answer")) { waiting.remove("${o.from}:${body.getString("re")}")?.complete(body.also { it.remove("__answer") }); return }
        // A request: answered once per (sender, id); a re-send gets the same answer (§5.3).
        val h = handlers[to] ?: return
        // A message with no id (a repair sigma) is handed on each time; only requests are answered once.
        val id = body.optString("id")
        val key = "${o.from}:$id"
        // Handlers run off the listener thread too, so one that sends and waits never blocks its own answer.
        handlerPool.execute {
            prune()
            val ans = (if (id.isNotEmpty()) answered[key]?.second else null) ?: (try { h(o.from, body, o.sentAt) } catch (_: Exception) { null } ?: return@execute).put("re", id).put("__answer", true).also { if (id.isNotEmpty()) answered[key] = now to it }
            for (part in Parts.split(ans)) publish(env.wrap(sk, o.from, part, now))
        }
    }

    fun connect(): RelayNet {
        for (r in relays) conns += Conn(r).also { it.dial() }
        return this
    }
    private fun sendAll(text: String) { for (c in conns) try { c.send(text) } catch (_: Exception) {} }
    /** Receive what is addressed to this key. */
    fun host(sk: ByteArray, pub: String, handler: ((String, JSONObject, Long) -> JSONObject?)? = null) {
        hosted[pub] = sk
        if (handler != null) handlers[pub] = handler
        val id = "kk-${pub.take(12)}"
        val req = { JSONArray(listOf("REQ", id, JSONObject().put("kinds", JSONArray(listOf(21059))).put("#p", JSONArray(listOf(pub))).put("since", now - CLOCK_SLACK_S))).toString() }
        subs[id] = req
        sendAll(req())
    }
    /** Publish a raw event to every relay. */
    fun publishEvent(e: JSONObject) = publish(e)
    /** To every relay, and to these too (a grant's own relays, dialled when not yet: Doors §3.3). */
    fun publishEventTo(e: JSONObject, urls: List<String>) { val extra = connsFor(urls).filter { c -> c.url !in relays }; publish(e); for (c in extra) try { c.send(JSONArray(listOf("EVENT", e)).toString()) } catch (_: Exception) {} }
    private val okWaits = ConcurrentHashMap<String, CompletableFuture<Any>>()
    private val eachWaits = ConcurrentHashMap<String, java.util.concurrent.CountDownLatch>()
    /** The relays named, dialled when not yet (at most 32 more than configured). */
    @Synchronized private fun connsFor(urls: List<String>): List<Conn> {
        for (u in urls) if (conns.none { it.url == u } && conns.size < relays.size + 32 && Regex("^wss?://\\S+$").matches(u) && u.length <= 256) conns += Conn(u).also { it.dial() }
        return conns.filter { it.url in urls }
    }
    /** Publish to exactly these relays: per relay `true` for an OK, or why it refused ("down" when unreachable). */
    fun publishTo(e: JSONObject, urls: List<String>, timeoutMs: Long = 4000): Map<String, Any> {
        val cs = connsFor(urls); val id = e.optString("id")
        val fs = cs.associate { c -> c.url to CompletableFuture<Any>().also { okWaits["${c.url} $id"] = it } }
        for (c in cs) try { c.send(JSONArray(listOf("EVENT", e)).toString()) } catch (_: Exception) {}
        val until = System.currentTimeMillis() + timeoutMs
        val out = LinkedHashMap<String, Any>()
        for (u in urls) out[u] = fs[u]?.let { f -> try { f.get(maxOf(1, until - System.currentTimeMillis()), TimeUnit.MILLISECONDS) } catch (_: Exception) { "down" } } ?: "down"
        for (c in cs) okWaits.remove("${c.url} $id")
        return out
    }
    /** Fetch from exactly these relays: the events, and which relays answered with EOSE. */
    fun queryEach(filter: JSONObject, urls: List<String>, timeoutMs: Long = 4000): Pair<List<Event>, List<String>> {
        val cs = connsFor(urls).filter { it.sock != null }
        val id = "ke-" + hex(ByteArray(6).also { java.security.SecureRandom().nextBytes(it) })
        val got = java.util.Collections.synchronizedList(ArrayList<JSONObject>())
        val latches = cs.associate { c -> c.url to java.util.concurrent.CountDownLatch(1).also { eachWaits["${c.url} $id"] = it } }
        queries[id] = got to java.util.concurrent.CountDownLatch(cs.size)
        for (c in cs) try { c.send(JSONArray(listOf("REQ", id, filter)).toString()) } catch (_: Exception) {}
        val until = System.currentTimeMillis() + timeoutMs
        for (l in latches.values) l.await(maxOf(1, until - System.currentTimeMillis()), TimeUnit.MILLISECONDS)
        val answered = latches.filter { it.value.count == 0L }.keys.toList()
        queries.remove(id); for (c in cs) { eachWaits.remove("${c.url} $id"); try { c.send(JSONArray(listOf("CLOSE", id)).toString()) } catch (_: Exception) {} }
        val evs = synchronized(got) { got.toList() }.mapNotNull { try { Event.of(it).takeIf(::verifyEvent) } catch (_: Exception) { null } }.distinctBy { it.id }
        return evs to answered
    }
    /** Subscribe to raw events; returns a function that stops it. */
    fun watch(filter: JSONObject, cb: (JSONObject) -> Unit, extra: List<String> = emptyList()): () -> Unit {
        if (extra.isNotEmpty()) connsFor(extra)
        val id = "kw-" + hex(ByteArray(6).also { java.security.SecureRandom().nextBytes(it) })
        watches[id] = cb to ConcurrentHashMap.newKeySet()
        val from = if (filter.has("since")) filter.getLong("since") else now - CLOCK_SLACK_S
        val req = { JSONArray(listOf("REQ", id, JSONObject(filter.toString()).put("since", maxOf(from, now - 600)))).toString() }
        subs[id] = req
        sendAll(req())
        return { watches.remove(id); subs.remove(id); sendAll(JSONArray(listOf("CLOSE", id)).toString()) }
    }
    private fun publish(w: JSONObject) = sendAll(JSONArray(listOf("EVENT", w)).toString())
    val now: Long get() = System.currentTimeMillis() / 1000
    private fun prune() {
        val t = now; if (t - pruned < 60) return
        pruned = t; answered.entries.removeIf { t - it.value.first > ANSWER_TTL_S }
    }
    /** Send `body` once, waiting for no answer (a join's closing `ack`, §4.2 step 5). */
    fun tell(sk: ByteArray, to: String, body: JSONObject) {
        if (!body.has("id")) body.put("id", hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }))
        for (part in Parts.split(body)) publish(env.wrap(sk, to, part, now))
    }

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
    fun close() { for (c in conns) { c.closed = true; try { c.sock?.close() } catch (_: Exception) {} }; redial.shutdownNow() }
}
