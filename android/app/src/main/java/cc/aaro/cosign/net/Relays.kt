package cc.aaro.cosign.net

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * One WebSocket per relay, one subscription, reconnect every 5 s when a relay
 * drops. Events are verified and deduplicated before anyone sees them.
 */
class Relays(
    private val urls: List<String>,
    private val onEvent: (Event) -> Unit,
    private val onChange: () -> Unit = {},
) {
    private val client = OkHttpClient.Builder().pingInterval(25, TimeUnit.SECONDS).connectTimeout(10, TimeUnit.SECONDS).build()
    private val sockets = ConcurrentHashMap<String, WebSocket>()
    private val open = ConcurrentHashMap.newKeySet<String>()
    private val seen = Collections.synchronizedSet(LinkedHashSet<String>())
    private val timer = Executors.newSingleThreadScheduledExecutor()
    @Volatile private var filter: Map<String, Any> = emptyMap()
    @Volatile private var stopped = false

    fun start(filter: Map<String, Any>) {
        this.filter = filter
        stopped = false
        urls.forEach(::connect)
    }

    fun stop() {
        stopped = true
        sockets.values.forEach { it.close(1000, null) }
        sockets.clear(); open.clear()
        onChange()
    }

    fun up(): Int = open.size

    fun publish(e: Event) {
        val frame = Json.stringify(listOf("EVENT", e.toMap()))
        for (url in open) sockets[url]?.send(frame)
    }

    private fun connect(url: String) {
        if (stopped) return
        val ws = client.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                open.add(url); onChange()
                // Member traffic is live; ask only for the last minute.
                val f = filter + ("since" to System.currentTimeMillis() / 1000 - 60)
                webSocket.send(Json.stringify(listOf("REQ", "cosign", f)))
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val msg = Json.parse(text) as? List<*> ?: return
                if (msg.getOrNull(0) != "EVENT") return
                val e = Event.fromMap(msg.getOrNull(2)) ?: return
                synchronized(seen) {
                    if (!seen.add(e.id)) return
                    if (seen.size > 4000) { val iter = seen.iterator(); repeat(2000) { iter.next(); iter.remove() } }
                }
                if (!e.verify()) return
                onEvent(e)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = dropped(url)
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = dropped(url)
        })
        sockets[url] = ws
    }

    private fun dropped(url: String) {
        open.remove(url); sockets.remove(url); onChange()
        if (!stopped) timer.schedule({ connect(url) }, 5, TimeUnit.SECONDS)
    }
}
