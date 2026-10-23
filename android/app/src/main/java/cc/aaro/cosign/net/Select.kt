package cc.aaro.cosign.net

import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.PairingUri
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

// Relay selection for the device that shows the QR (§11.3a). A relay is named in the
// QR only after it passes a loopback test in this session. Candidates, in order: what
// the user configured, what passed here before, what a scanned QR named, then seeds.

val SEEDS = listOf(
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr.mom",
    "wss://relay.nostr.net",
    "wss://offchain.pub",
    "wss://nostr.oxtr.dev",
    "wss://relay.0xchat.com",
)

const val TARGET_RELAYS = 3
private const val BATCH = 4
private const val GRACE_MS = 1200L
/** Pause before working through the list again when nothing passed, doubling each round (§11.3). */
private val RETRY_MS = longArrayOf(5_000, 15_000, 30_000, 60_000)

enum class ProgressState { TESTING, LISTED, SPARE, FAILED }

data class RelayProgress(val url: String, val source: Source, val state: ProgressState, val why: String? = null)

/** Why NIP-11's advertised limits rule a relay out for this probe (§11.6), or null. */
fun ruledOut(http: OkHttpClient, url: String, probe: Event): String? {
    val request = try {
        Request.Builder().url(url.replaceFirst("wss://", "https://").replaceFirst("ws://", "http://"))
            .header("Accept", "application/nostr+json").build()
    } catch (_: Exception) { return null }
    val client = http.newBuilder().callTimeout(2500, TimeUnit.MILLISECONDS).build()
    val doc = try {
        client.newCall(request).execute().use { if (!it.isSuccessful) return null; JSONObject(it.body?.string() ?: return null) }
    } catch (_: Exception) { return null }
    val limits = doc.optJSONObject("limitation") ?: return null
    if (limits.optBoolean("payment_required", false)) return "requires payment"
    val content = limits.optLong("max_content_length", 0)
    if (content > 0 && probe.content.length > content) return "advertises a content limit of $content, below what this profile needs"
    val message = limits.optLong("max_message_length", 0)
    val bytes = ("[\"EVENT\"," + probe.toJson() + "]").toByteArray().size
    if (message > 0 && bytes > message) return "advertises a message limit of $message, below what this profile needs"
    return null
}

/**
 * Works through the candidates until some pass, and keeps working through them for as
 * long as `alive()` (the session) lasts (§11.3). Blocks; run it off the main thread.
 */
fun selectRelays(
    pool: Pool,
    store: Store,
    probe: () -> Event,
    alive: () -> Boolean,
    onProgress: (List<RelayProgress>) -> Unit,
): List<String> {
    val progress = LinkedHashMap<String, RelayProgress>()
    fun report() = onProgress(progress.values.toList())
    val workers = Executors.newFixedThreadPool(BATCH)
    try {
        var round = 0
        while (alive()) {
            val candidates = LinkedHashMap<String, Source>()
            fun offer(urls: List<String>, source: Source) {
                for (raw in urls) {
                    val url = PairingUri.normalizeRelayUrl(raw) ?: continue
                    // A relay that rate-limited this device recently is left alone for a while.
                    if (store.isResting(url)) continue
                    // A private-network relay is used only if the user configured it.
                    if (source != Source.CONFIGURED && runCatching { PairingUri.isPrivateHost(java.net.URI(url).host) }.getOrDefault(true)) continue
                    candidates.putIfAbsent(url, source)
                }
            }
            offer(store.configured(), Source.CONFIGURED)
            offer(store.remembered(), Source.REMEMBERED)
            offer(store.learned(), Source.LEARNED)
            val known = candidates.size
            offer(SEEDS, Source.SEED)

            val passed = ArrayList<String>()
            var firstPassAt = 0L
            val queue = candidates.entries.toMutableList()
            var tested = 0
            while (queue.isNotEmpty() && alive()) {
                // Seeds only once nothing known has passed (§11.3a, item 4).
                if (tested >= known && passed.isNotEmpty()) break
                val batch = queue.take(BATCH).also { queue.subList(0, it.size).clear() }
                tested += batch.size
                for ((url, source) in batch) progress[url] = RelayProgress(url, source, ProgressState.TESTING)
                report()
                val futures = batch.map { (url, source) ->
                    workers.submit(Callable {
                        val p = probe()
                        pool.ignore(p.id)
                        val why = ruledOut(pool.http, url, p)
                        val result = if (why != null) false to why else pool.loopback(url, p)
                        Triple(url, source, result)
                    })
                }
                for (f in futures) {
                    val (url, source, result) = try { f.get(20, TimeUnit.SECONDS) } catch (_: Exception) { continue }
                    if (result.first) {
                        store.notePassed(url)
                        passed += url
                        if (firstPassAt == 0L) firstPassAt = System.currentTimeMillis()
                        progress[url] = RelayProgress(url, source, if (passed.size <= TARGET_RELAYS) ProgressState.LISTED else ProgressState.SPARE)
                    } else {
                        if (result.second?.contains("rate-limited") == true) store.noteRateLimited(url)
                        else if (source == Source.REMEMBERED) store.noteFailed(url)
                        progress[url] = RelayProgress(url, source, ProgressState.FAILED, result.second)
                    }
                    report()
                }
                if (passed.size >= TARGET_RELAYS) break
                if (passed.isNotEmpty() && System.currentTimeMillis() - firstPassAt > GRACE_MS) break
            }
            if (passed.isNotEmpty()) {
                // Spares stay out of the code; close them.
                for (url in passed.drop(TARGET_RELAYS)) pool.post { pool.remove(url) }
                return passed.take(TARGET_RELAYS)
            }
            Thread.sleep(RETRY_MS[minOf(round++, RETRY_MS.size - 1)])
        }
        return emptyList()
    } finally {
        workers.shutdownNow()
    }
}
