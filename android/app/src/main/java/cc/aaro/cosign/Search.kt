package cc.aaro.cosign

import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.isHex32
import cc.aaro.cosign.net.Fetch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.math.log10

// Finding people, as the user's Wisp does it (~/src/wisp, commits f51ab1c and 0634e29): the two
// search relays that answer fastest first (syb.lol, and relay.ditto.pub with the big database),
// the slower ones as fallbacks; your follows before anyone; a pasted address opens what it names.
// Ranked: the exact name, a checked NIP-05, then trust (your follows, theirs, everyone's).

object SearchRelays {
    /** Asked first, together: they answer in well under a second. */
    val FAST = listOf("wss://syb.lol", "wss://relay.ditto.pub")
    /** Slower, with a short wait: whatever they add comes in after. */
    val SLOW = listOf("wss://search.nos.today", "wss://search.nostrarchives.com")
    /** Count followers (NIP-45), both at once; the higher count wins (relay.ditto.pub's database is the bigger, syb.lol answers when it's busy). */
    val COUNTS = listOf("wss://relay.ditto.pub", "wss://syb.lol")
}

/** What we know about someone a search found: enough to put them in order. */
data class Hit(
    val pubkey: String,
    val name: String?,
    /** Where the relays put them, first seen first. */
    val order: Int,
    val follow: Boolean = false,
    /** How many of the people you follow follow them. */
    val fof: Int = 0,
    val followers: Long? = null,
    val nip05: Nip05.Check = Nip05.Check.NONE,
)

object SearchRank {
    /** A name as typed: lower case, the emoji and signs around it gone, spaces single. */
    fun norm(s: String) = s.lowercase().replace(Regex("[^\\p{L}\\p{N}]+"), " ").trim()

    fun exact(name: String?, q: String) = name != null && norm(name) == norm(q) && norm(q).isNotEmpty()
    fun matches(name: String?, q: String) = name != null && norm(q).isNotEmpty() && norm(q) in norm(name)

    /**
     * How much to trust someone, for the order among the same kind of match: a NIP-05 that checks out
     * counts for a lot and one that names another key counts against; the people you follow following
     * them; then everyone's follows, on a log scale (174,000 followers against 19,000 is less than one step).
     */
    fun trust(h: Hit): Double {
        val n = when (h.nip05) { Nip05.Check.OK -> 1.5; Nip05.Check.WRONG -> -2.0; else -> 0.0 }
        val friends = if (h.fof > 0) 2.0 + 2 * log10(h.fof + 1.0) else 0.0
        return n + friends + log10((h.followers ?: 0) + 1.0)
    }

    /** Your follows first, then exact names, then the rest; within each, the most trusted first, then the relays' order. */
    fun sort(hits: Collection<Hit>, q: String): List<Hit> {
        val nq = norm(q)
        // Worked out once per person, not on every comparison.
        return hits.map { Triple(it, nq.isNotEmpty() && it.name != null && norm(it.name) == nq, trust(it)) }.sortedWith(
            compareByDescending<Triple<Hit, Boolean, Double>> { it.first.follow }
                .thenByDescending { it.second }
                .thenByDescending { it.third }
                .thenBy { it.first.order },
        ).map { it.first }
    }
}

/** NIP-05: does name@domain name this key? Asked once per address and remembered. */
object Nip05 {
    enum class Check { NONE, OK, WRONG, UNKNOWN }
    private val checked = ConcurrentHashMap<String, Pair<Check, Long>>()
    private val http by lazy { Fetch.http.newBuilder().callTimeout(3, TimeUnit.SECONDS).followRedirects(false).build() }
    private val ADDRESS = Regex("^([a-zA-Z0-9._+-]*)@([a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*\\.[a-zA-Z]{2,})$")

    fun isAddress(s: String) = ADDRESS.matches(s.trim())

    /** OK, WRONG (the domain names another key), or UNKNOWN (no answer: not held against them). */
    suspend fun check(pubkey: String, address: String?): Check {
        val a = address?.trim()?.lowercase()?.takeIf { isAddress(it) } ?: return Check.NONE
        val key = "$a $pubkey"
        checked[key]?.let { (c, at) -> if (System.currentTimeMillis() - at < 6 * 3_600_000L) return c }
        val c = when (lookup(a)) { null -> Check.UNKNOWN; pubkey -> Check.OK; else -> Check.WRONG }
        checked[key] = c to System.currentTimeMillis()
        return c
    }

    /** The key name@domain stands for; "" when the domain answers without it; null when it doesn't answer. */
    suspend fun lookup(address: String): String? = withContext(Dispatchers.IO) {
        val m = ADDRESS.matchEntire(address.trim().lowercase()) ?: return@withContext null
        val name = m.groupValues[1].ifEmpty { "_" }
        try {
            http.newCall(okhttp3.Request.Builder().url("https://${m.groupValues[2]}/.well-known/nostr.json?name=$name").build()).execute().use { r ->
                if (!r.isSuccessful) return@use null
                val names = (Json.parse(r.body?.string().orEmpty()) as? Map<*, *>)?.get("names") as? Map<*, *> ?: return@use ""
                (names[name] as? String)?.lowercase()?.takeIf { isHex32(it) } ?: ""
            }
        } catch (_: Exception) { null }
    }
}
