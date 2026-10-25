package cc.aaro.cosign.net

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

// Relay transport for one session (spec §11.5). A port of src/web/pool.ts.
//
// Wraps are ephemeral (kind 21059): a relay passes one to whoever is subscribed at
// that moment and keeps nothing. So the outbox is a retransmit loop: every few
// seconds, whenever a socket opens or authenticates, and when the app comes back to
// the foreground, each outstanding message goes out again in a fresh wrap.
//
// Threading: every method here runs on `loop`, one thread. Socket callbacks hop onto it.

enum class LinkState { CONNECTING, OPEN, CLOSED }

class Outgoing(
    var event: Event,
    val again: (() -> Event)?,
    val to: String?,
    val kind: Int?,
    val unanswered: Boolean,
) {
    /** When it stops going out (ms); null for as long as it is outstanding. */
    var until: Long? = null
}

data class Ack(val ok: Boolean, val message: String)

class PoolOptions(
    val filter: Map<String, Any>,
    val signAuth: (url: String, challenge: String) -> Event,
    val onEvent: (Event, String) -> Unit,
    val onChange: () -> Unit = {},
    val resendMs: Long = RESEND_MS,
    val finalMs: Long = FINAL_RESEND_MS,
)

const val RESEND_MS = 3000L
const val FINAL_RESEND_MS = 20_000L
private val BACKOFF_MS = longArrayOf(500, 1000, 2000, 4000, 8000)

/** Text from a relay is shown, so it is cut short and stripped of control characters. */
private fun tidy(text: Any?, fallback: String): String {
    if (text !is String || text.isEmpty()) return fallback
    return text.replace(Regex("[\\u0000-\\u001f\\u007f]"), " ").take(120)
}

class RelayLink(val url: String, private val pool: Pool, private val options: PoolOptions, var reconnect: Boolean) {
    var state = LinkState.CONNECTING
        private set
    var lastReason: String? = null
    val acks = HashMap<String, Ack>()
    private var ws: WebSocket? = null
    private val subId = "q" + java.lang.Long.toString((Math.random() * 1e12).toLong(), 36)
    private var challenge: String? = null
    private var authId: String? = null
    private var authed = false
    private var attempt = 0
    var restUntil = 0L
    private var rests = 0
    private var timer: ScheduledFuture<*>? = null
    private var closedByUs = false
    private val local = ArrayList<Event>()

    init { connect() }

    private fun connect() {
        if (closedByUs) return
        state = LinkState.CONNECTING
        authed = false; authId = null; challenge = null
        val request = try { Request.Builder().url(url.replaceFirst("wss://", "https://").replaceFirst("ws://", "http://")).build() } catch (e: Exception) {
            lastReason = "bad address"; onClose(null); return
        }
        lateinit var socket: WebSocket
        socket = pool.http.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) = pool.post {
                if (ws !== socket) return@post
                state = LinkState.OPEN
                attempt = 0
                subscribe()
                republish()
                pool.changed()
            }
            override fun onMessage(webSocket: WebSocket, text: String) = pool.post { if (ws === socket) onMessage(text) }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { webSocket.close(1000, null) }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = pool.post { if (ws === socket) onClose(socket) }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = pool.post {
                if (ws === socket) { lastReason = tidy(t.message, "could not connect"); onClose(socket) }
            }
        })
        ws = socket
    }

    private fun onClose(socket: WebSocket?) {
        ws = null
        state = LinkState.CLOSED
        pool.changed()
        if (closedByUs || !reconnect) return
        // §11.3: keep re-attempting an unreachable relay for the remaining lifetime of the session.
        val wait = BACKOFF_MS[minOf(attempt++, BACKOFF_MS.size - 1)]
        timer = pool.schedule(wait) { connect() }
    }

    private fun raw(message: List<Any>) {
        if (state == LinkState.OPEN) ws?.send(Json.stringify(message))
    }

    private fun rawEvent(type: String, e: Event) {
        if (state == LinkState.OPEN) ws?.send("[\"$type\"," + e.toJson() + "]")
    }

    private fun subscribe() = raw(listOf("REQ", subId, options.filter))

    private fun republish() {
        pool.resend(this)
        for (e in local) rawEvent("EVENT", e)
    }

    fun wake() {
        if (closedByUs || state != LinkState.CLOSED || !reconnect) return
        timer?.cancel(false)
        attempt = 0
        connect()
    }

    private fun authenticate() {
        val c = challenge ?: return
        if (authId != null) return
        val event = try { options.signAuth(url, c) } catch (_: Exception) { return }
        authId = event.id
        rawEvent("AUTH", event)
    }

    private fun onMessage(data: String) {
        val message = Json.parse(data) as? List<*> ?: return
        val type = message.getOrNull(0)
        val a = message.getOrNull(1)
        val b = message.getOrNull(2)
        val c = message.getOrNull(3)
        when (type) {
            "EVENT" -> if (a == subId) pool.incoming(this, b)
            "OK" -> {
                if (a !is String) return
                val ok = b == true
                val text = tidy(c, "")
                if (a == authId) {
                    if (ok) {
                        // §11.5: a relay may take a publish and only then demand AUTH, so everything goes again.
                        authed = true
                        subscribe()
                        republish()
                    } else {
                        lastReason = text.ifEmpty { "authentication refused" }
                        authId = null
                    }
                    pool.changed()
                    return
                }
                acks[a] = Ack(ok, text)
                if (ok) rests = 0
                else if (text.startsWith("rate-limited")) {
                    restUntil = System.currentTimeMillis() + minOf(60_000L, 10_000L shl rests++)
                }
                if (!ok) {
                    lastReason = text.ifEmpty { "refused" }
                    if (text.startsWith("auth-required") && !authed) authenticate() else pool.refused(this, a)
                }
                pool.changed()
            }
            "CLOSED" -> {
                if (a != subId) return
                lastReason = tidy(b, "subscription closed")
                if (lastReason!!.startsWith("auth-required") && !authed) authenticate()
                pool.changed()
            }
            "AUTH" -> {
                if (a !is String) return
                challenge = a
                authId = null
                authenticate()
            }
            "NOTICE" -> lastReason = tidy(a, "notice")
        }
    }

    fun publish(event: Event) = rawEvent("EVENT", event)

    fun publishLocal(event: Event) {
        local += event
        rawEvent("EVENT", event)
    }

    fun clearLocal() = local.clear()

    fun close() {
        closedByUs = true
        timer?.cancel(false)
        val socket = ws
        ws = null
        state = LinkState.CLOSED
        socket?.close(1000, null)
    }
}

class Pool(private val options: PoolOptions, val loop: ScheduledExecutorService, val http: OkHttpClient) {
    private val outbox = ArrayList<Outgoing>()
    private val links = LinkedHashMap<String, RelayLink>()
    private val seen = HashSet<String>()
    private val ignored = HashSet<String>()
    private val waiters = HashMap<String, (Boolean) -> Unit>()
    private var closed = false
    private var ending = false
    private var resendTimer: ScheduledFuture<*>? = null

    val isClosed get() = closed || ending

    fun post(block: () -> Unit) {
        try { loop.execute { try { block() } catch (e: Exception) { e.printStackTrace() } } } catch (_: Exception) {}
    }

    fun schedule(ms: Long, block: () -> Unit): ScheduledFuture<*>? =
        try { loop.schedule({ try { block() } catch (e: Exception) { e.printStackTrace() } }, ms, TimeUnit.MILLISECONDS) } catch (_: Exception) { null }

    fun changed() { if (!closed) options.onChange() }

    fun add(url: String, reconnect: Boolean): RelayLink {
        links[url]?.let { it.reconnect = it.reconnect || reconnect; return it }
        val link = RelayLink(url, this, options, reconnect)
        links[url] = link
        return link
    }

    fun remove(url: String) {
        links.remove(url)?.close()
        changed()
    }

    fun get(url: String) = links[url]
    fun all(): List<RelayLink> = links.values.toList()

    /** Publishes to every relay in parallel and keeps the message to send again (§11.5). */
    fun publish(message: Outgoing) {
        if (closed) return
        if (message.unanswered) message.until = System.currentTimeMillis() + options.finalMs
        outbox += message
        for (link in links.values) link.publish(message.event)
        if (resendTimer == null) {
            resendTimer = loop.scheduleWithFixedDelay({ post { tick() } }, options.resendMs, options.resendMs, TimeUnit.MILLISECONDS)
        }
    }

    fun settle(to: String, kinds: Collection<Int>) {
        outbox.removeAll { it.to == to && it.kind != null && it.kind in kinds }
    }

    fun resend(only: RelayLink? = null) {
        if (closed) return
        val now = System.currentTimeMillis()
        for (e in outbox.toList()) if (e.until.let { it == null || now < it }) again(e, only, false)
    }

    private fun again(e: Outgoing, only: RelayLink?, timed: Boolean) {
        e.again?.let { fresh -> e.event = try { fresh() } catch (_: Exception) { return } }
        if (only != null) only.publish(e.event)
        else for (link in links.values) if (!timed || System.currentTimeMillis() >= link.restUntil) link.publish(e.event)
    }

    private fun tick() {
        if (closed) return
        val now = System.currentTimeMillis()
        for (e in outbox.toList()) if (e.until.let { it == null || now < it }) again(e, null, true)
    }

    /** Reconnects what is down and sends everything outstanding again, now. */
    fun wake() {
        if (closed) return
        for (link in links.values) link.wake()
        resend()
    }

    fun ignore(id: String) { ignored += id }

    fun incoming(link: RelayLink, raw: Any?) {
        if (closed) return
        val event = Event.fromMap(raw) ?: return
        if (event.id.isEmpty()) return
        // A probe passes only if what came back is the event that went out (§11.5).
        val waiter = waiters["${link.url} ${event.id}"]
        if (waiter != null && event.verify()) waiter(true)
        if (event.id in ignored) return
        // Dedupe only after the signature holds, or junk under a real id would hide the genuine copy.
        if (event.id in seen) return
        if (!event.verify()) return
        seen += event.id
        options.onEvent(event, link.url)
    }

    fun refused(link: RelayLink, id: String) {
        waiters["${link.url} $id"]?.invoke(false)
    }

    /**
     * The loopback test of §11.3a, from a background thread: opens a link, publishes
     * `probe` to that relay alone, and passes only if the same event comes back.
     */
    fun loopback(url: String, probe: Event, echoMs: Long = 3000, connectMs: Long = 5000): Pair<Boolean, String?> {
        if (isClosed) return false to "cancelled"
        val link = onLoop { add(url, false) } ?: return false to "cancelled"
        val fail = { reason: String -> post { remove(url) }; false to reason }
        val opened = until(connectMs) { link.state == LinkState.OPEN || link.state == LinkState.CLOSED }
        if (isClosed) return false to "cancelled"
        if (!opened || link.state != LinkState.OPEN) return fail("could not connect")

        val key = "$url ${probe.id}"
        val result = java.util.concurrent.CompletableFuture<Boolean>()
        onLoop {
            waiters[key] = { echo -> waiters.remove(key); result.complete(echo) }
            link.publishLocal(probe)
        }
        val ok = try { result.get(echoMs, TimeUnit.MILLISECONDS) } catch (_: Exception) { false }
        onLoop { waiters.remove(key) }
        if (isClosed) return false to "cancelled"
        if (!ok) {
            val ack = onLoop { link.acks[probe.id] }
            return when {
                ack != null && !ack.ok -> fail("refused: ${ack.message.ifEmpty { "no reason given" }}")
                ack?.ok == true -> fail("accepted the event but did not deliver it")
                else -> fail(link.lastReason?.let { "no answer ($it)" } ?: "no answer")
            }
        }
        onLoop { link.clearLocal(); link.reconnect = true; changed() }
        return true to null
    }

    /** Runs on the loop and waits for the answer. Never call from the loop itself. */
    fun <R> onLoop(block: () -> R): R? = try { loop.submit<R> { block() }.get(5, TimeUnit.SECONDS) } catch (_: Exception) { null }

    private fun until(ms: Long, condition: () -> Boolean): Boolean {
        val started = System.currentTimeMillis()
        while (true) {
            if (onLoop(condition) == true) return true
            if (closed || System.currentTimeMillis() - started >= ms) return false
            Thread.sleep(25)
        }
    }

    /**
     * The session has ended. What was waiting for an answer is dropped; the last messages
     * (an ACK, an ABORT) go out their remaining times, and then the pool closes.
     */
    fun windDown() {
        if (closed || ending) return
        ending = true
        outbox.removeAll { it.until == null }
        val last = (outbox.mapNotNull { it.until } + System.currentTimeMillis()).max()
        schedule(last - System.currentTimeMillis() + 2500) { close() }
    }

    fun close() {
        closed = true
        resendTimer?.cancel(false)
        for (link in links.values) link.close()
        links.clear()
        waiters.clear()
    }
}
