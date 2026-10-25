package cc.aaro.cosign.net

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Finding servers (COSIGN.md §9.5), as site/src/servers.ts does: announcements (kind
 * 30243, d = "cosign-server", signed by a server's host key, naming its operator) found on
 * a few relays, plus a seed list the app vouches for. Blocking; never on the main thread.
 */
object Servers {
    data class Server(val pk: String, val relays: List<String>, val enroll: String, val version: String, val operator: String, val name: String) : java.io.Serializable

    /** Servers known to be run by the people named: the same list as servers.ts's SEEDS. */
    private val SEEDS = listOf(
        Server("040e022d19ed8e0ba6d83f6246b9d051f0093e59092ee6bb279730d0e4b191c8", listOf("wss://syb.lol", "wss://nos.lol", "wss://relay.primal.net"), "open", "", "f5073ea24832d8e6246d22ec0b5a75bbf4a12558e3ac67cb07360b3474e5a40e", "syb.lol"),
        Server("665dd9c0ececdb5b60868aa6c0860df9f8e9e40c65304a9ffcecc59aa1502420", listOf("wss://cosign-cf.aaro.cc"), "open", "", "f5073ea24832d8e6246d22ec0b5a75bbf4a12558e3ac67cb07360b3474e5a40e", "cosign-cf.aaro.cc"),
        Server("b3bb4b39a719e7f647cf30aca77f54facd8634b3ae575eb3c527200ac51502ae", listOf("wss://syb.lol", "wss://nos.lol", "wss://relay.primal.net"), "open", "", "f5073ea24832d8e6246d22ec0b5a75bbf4a12558e3ac67cb07360b3474e5a40e", "Cosign server 3"),
    )
    private val DISCOVERY = listOf("wss://syb.lol", "wss://relay.primal.net", "wss://nos.lol", "wss://relay.damus.io")
    private val http = OkHttpClient.Builder().connectTimeout(5, TimeUnit.SECONDS).build()

    /** Seeds, then any announced server whose operator is a seed's (no operator lists in the app yet), newest announcement each. */
    fun find(): List<Server> {
        debugServers()?.let { return it }
        val found = ConcurrentHashMap<String, Pair<Long, Server>>()
        val latch = CountDownLatch(DISCOVERY.size)
        for (url in DISCOVERY) {
            var done = false
            http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
                override fun onOpen(ws: WebSocket, response: okhttp3.Response) {
                    ws.send(Json.stringify(listOf("REQ", "s", mapOf("kinds" to listOf(30243), "#d" to listOf("cosign-server")))))
                }
                override fun onMessage(ws: WebSocket, text: String) {
                    val m = Json.parse(text) as? List<*> ?: return
                    when (m.getOrNull(0)) {
                        "EVENT" -> parse(Event.fromMap(m.getOrNull(2)) ?: return)?.let { (at, s) -> found.merge(s.pk, at to s) { a, b -> if (a.first >= b.first) a else b } }
                        "EOSE" -> { ws.close(1000, null); if (!done) { done = true; latch.countDown() } }
                    }
                }
                override fun onFailure(ws: WebSocket, t: Throwable, response: okhttp3.Response?) { if (!done) { done = true; latch.countDown() } }
            })
        }
        latch.await(6, TimeUnit.SECONDS)
        val operators = SEEDS.map { it.operator }.toSet()
        val announced = found.values.map { it.second }.filter { it.operator in operators }
        return (SEEDS.map { seed -> announced.firstOrNull { it.pk == seed.pk } ?: seed } + announced.filter { a -> SEEDS.none { it.pk == a.pk } })
            .filter { it.enroll == "open" }
    }

    /**
     * Debug builds only: servers listed in files/debug-servers.json (`[{"pk", "relays", "name",
     * "operator"}]`, written with `adb shell run-as`), instead of the public ones, so trying
     * Create or an import leaves nothing on real servers.
     */
    private fun debugServers(): List<Server>? {
        val app = cc.aaro.cosign.CosignApp.instance
        if (app.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE == 0) return null
        val f = java.io.File(app.filesDir, "debug-servers.json").takeIf { it.exists() } ?: return null
        return (Json.parse(f.readText()) as? List<*>)?.mapNotNull { it as? Map<*, *> }?.map {
            Server(it["pk"] as String, (it["relays"] as List<*>).map { r -> r as String }, "open", "", it["operator"] as? String ?: it["pk"] as String, it["name"] as? String ?: "Test server")
        }
    }

    private fun parse(e: Event): Pair<Long, Server>? {
        if (e.kind != 30243 || e.firstTag("d") != "cosign-server" || !e.verify()) return null
        val operator = e.tags.firstOrNull { it.size >= 4 && it[0] == "p" && it[3] == "operator" }?.get(1) ?: return null
        val c = Json.parse(e.content) as? Map<*, *> ?: return null
        val relays = (c["relays"] as? List<*>)?.filterIsInstance<String>()?.filter { it.startsWith("wss://") } ?: return null
        if (relays.isEmpty()) return null
        val https = (c["https"] as? String)?.removePrefix("https://")?.trimEnd('/')
        val name = e.firstTag("nip05") ?: https ?: relays[0].removePrefix("wss://")
        return e.createdAt to Server(e.pubkey, relays, if (c["enroll"] == "open") "open" else "invite", c["version"] as? String ?: "", operator, name)
    }
}
