package cc.aaro.cosign.net

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Reading Nostr for the home screen: ask some relays once, take what they have, hang up.
 * Nothing stays subscribed, so nothing runs while the screen is off. Every event is
 * checked (id and signature) before anyone sees it.
 */
object Fetch {
    val http: OkHttpClient = OkHttpClient.Builder().connectTimeout(6, TimeUnit.SECONDS).build()

    /**
     * What [relays] hold for [filters], until each has said it's done or [timeoutMs] passes.
     * Once one relay is done, the slow ones get [graceMs] more: one stuck relay mustn't hold up a screen.
     */
    suspend fun query(relays: Collection<String>, filters: List<Map<String, Any>>, timeoutMs: Long = 7000, graceMs: Long = 2500): List<Event> =
        runInterruptible(Dispatchers.IO) { queryBlocking(relays.distinct(), filters, timeoutMs, graceMs) }

    suspend fun query(relays: Collection<String>, filter: Map<String, Any>, timeoutMs: Long = 7000) = query(relays, listOf(filter), timeoutMs)

    private fun queryBlocking(relays: List<String>, filters: List<Map<String, Any>>, timeoutMs: Long, graceMs: Long): List<Event> {
        if (relays.isEmpty()) return emptyList()
        // In the order they arrive: a curated feed's order is its ranking.
        val got = java.util.Collections.synchronizedMap(LinkedHashMap<String, Event>())
        val done = CountDownLatch(relays.size)
        val firstDone = java.util.concurrent.atomic.AtomicLong()
        val sub = "c" + java.lang.Long.toString((Math.random() * 1e12).toLong(), 36)
        val req = Json.stringify(listOf("REQ", sub) + filters)
        val sockets = relays.mapNotNull { url ->
            val once = java.util.concurrent.atomic.AtomicBoolean(false)
            val finish = { ws: WebSocket -> if (once.compareAndSet(false, true)) { done.countDown(); ws.close(1000, null) } }
            try {
                http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) { webSocket.send(req) }
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val msg = Json.parse(text) as? List<*> ?: return
                        if (msg.getOrNull(1) != sub) return
                        when (msg.getOrNull(0)) {
                            "EVENT" -> Event.fromMap(msg.getOrNull(2))?.let { e -> if (!got.containsKey(e.id) && e.verify()) got[e.id] = e }
                            "EOSE", "CLOSED" -> { firstDone.compareAndSet(0L, System.currentTimeMillis()); finish(webSocket) }
                        }
                    }
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { if (once.compareAndSet(false, true)) done.countDown() }
                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { if (once.compareAndSet(false, true)) done.countDown() }
                })
            } catch (_: Exception) { done.countDown(); null }
        }
        val end = System.currentTimeMillis() + timeoutMs
        try {
            while (!done.await(100, TimeUnit.MILLISECONDS)) {
                val now = System.currentTimeMillis()
                if (now >= end || (firstDone.get() != 0L && now - firstDone.get() >= graceMs)) break
            }
        } finally { sockets.forEach { it.cancel() } }
        return synchronized(got) { got.values.toList() }
    }

    /** Send [event] to [relays]; how many took it. */
    suspend fun publish(relays: Collection<String>, event: Event, timeoutMs: Long = 6000): Int = runInterruptible(Dispatchers.IO) {
        val urls = relays.distinct()
        val ok = AtomicInteger()
        val done = CountDownLatch(urls.size)
        val frame = "[\"EVENT\"," + event.toJson() + "]"
        val sockets = urls.mapNotNull { url ->
            val once = java.util.concurrent.atomic.AtomicBoolean(false)
            try {
                http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) { webSocket.send(frame) }
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val msg = Json.parse(text) as? List<*> ?: return
                        if (msg.getOrNull(0) == "OK" && msg.getOrNull(1) == event.id && once.compareAndSet(false, true)) {
                            if (msg.getOrNull(2) == true) ok.incrementAndGet()
                            done.countDown(); webSocket.close(1000, null)
                        }
                    }
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { if (once.compareAndSet(false, true)) done.countDown() }
                })
            } catch (_: Exception) { done.countDown(); null }
        }
        try { done.await(timeoutMs, TimeUnit.MILLISECONDS) } finally { sockets.forEach { it.cancel() } }
        ok.get()
    }
}
