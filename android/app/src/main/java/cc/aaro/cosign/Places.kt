package cc.aaro.cosign

import android.content.Context
import cc.aaro.cosign.core.Clock
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.net.Fetch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.Base64
import java.util.concurrent.TimeUnit

// Places you're signed in to (your video site first) that put a few things of their own into
// Discover. Each is a PlaceFeed: it says where it is, what to call it, and fetches its cards.

/** One thing from a place, shown as a card in Discover: a video, for now. */
data class PlaceCard(
    val id: String, val title: String, val channel: String, val thumb: String?, val url: String,
    /** Seconds, if it's a video. */
    val duration: Int?, val published: Long?, val label: String,
)

interface PlaceFeed {
    val origin: String
    val label: String
    /** Its cards for you; null when this account isn't allowed there (hide it); empty when it has nothing. */
    suspend fun fetch(): List<PlaceCard>?
}

/**
 * Tube (tube.syb.lol): "for you" videos, after a NIP-98 login signed once by your account
 * and kept as a session. [sign] signs the login event the way your likes are signed.
 */
class TubeFeed(context: Context, slot: String, private val me: () -> String?, private val sign: (Event) -> Event) : PlaceFeed {
    override val origin = "https://tube.syb.lol"
    override val label = "Tube"
    private val prefs = context.getSharedPreferences("places.$slot", Context.MODE_PRIVATE)
    private val http = Fetch.http.newBuilder().callTimeout(8, TimeUnit.SECONDS).followRedirects(false).build()

    override suspend fun fetch(): List<PlaceCard>? = withContext(Dispatchers.IO) {
        // Turned away lately, or the login didn't work: don't sign another one every time Discover opens.
        if (System.currentTimeMillis() < prefs.getLong("tube.wait", 0)) return@withContext null
        // Ask first; sign a login only when Tube says who are you. Not there yet, or down: nothing, and no signing.
        var session = prefs.getString("tube.session", null)
        repeat(2) { attempt ->
            val req = Request.Builder().url("$origin/api/for-you?limit=6").apply { session?.let { header("Cookie", it) } }.build()
            http.newCall(req).execute().use { r ->
                when {
                    r.isSuccessful -> return@withContext parse(r.body?.string().orEmpty())
                    (r.code == 401 || r.code == 403) && attempt == 0 -> { prefs.edit().remove("tube.session").apply(); session = login() ?: return@withContext null }
                    r.code == 401 || r.code == 403 -> { denied(); return@withContext null }
                    else -> return@withContext emptyList()
                }
            }
        }
        emptyList()
    }

    /** NIP-98: a kind 27235 event naming the URL and method, in the Authorization header. */
    private fun login(): String? {
        if (me() == null) return null
        val url = "$origin/api/login"
        val ev = try { sign(Event(me()!!, Clock.now(), 27235, listOf(listOf("u", url), listOf("method", "POST")), "").withId()) } catch (_: Exception) { return null }
        val auth = "Nostr " + Base64.getEncoder().encodeToString(ev.toJson().toByteArray())
        return try {
            http.newCall(Request.Builder().url(url).header("Authorization", auth).post(ByteArray(0).toRequestBody("application/json".toMediaType())).build()).execute().use { r ->
                if (r.code == 401 || r.code == 403) { denied(); return null }
                val cookie = r.headers("Set-Cookie").joinToString("; ") { it.substringBefore(';') }
                if (!r.isSuccessful || cookie.isEmpty()) { backOff(6 * 3_600_000L); return null }
                prefs.edit().putString("tube.session", cookie).remove("tube.wait").apply()
                cookie
            }
        } catch (_: Exception) { null }
    }

    private fun denied() { backOff(86_400_000L); prefs.edit().remove("tube.session").apply() }
    private fun backOff(ms: Long) = prefs.edit().putLong("tube.wait", System.currentTimeMillis() + ms).apply()

    private fun parse(body: String): List<PlaceCard> {
        val root = try { Json.parse(body) } catch (_: Exception) { return emptyList() }
        val list = (root as? List<*>) ?: ((root as? Map<*, *>)?.let { it["items"] ?: it["videos"] } as? List<*>) ?: return emptyList()
        return list.mapNotNull { x ->
            val m = x as? Map<*, *> ?: return@mapNotNull null
            val url = (m["url"] as? String)?.takeIf { it.startsWith("https://") } ?: return@mapNotNull null
            PlaceCard((m["id"] ?: url).toString(), (m["title"] as? String ?: "").take(140), (m["channel"] as? String ?: "").take(60),
                (m["thumb"] as? String)?.takeIf { it.startsWith("https://") }, url, (m["duration"] as? Long)?.toInt(), m["published"] as? Long, label)
        }.take(6)
    }
}

/** Debug builds only: stand-in videos, until Tube's endpoint is live. */
class FakeTube : PlaceFeed {
    override val origin = "https://tube.syb.lol"
    override val label = "Tube"
    override suspend fun fetch(): List<PlaceCard> {
        delay(400)
        val titles = listOf("Building a bike trailer from scrap" to "Workshop Days", "Night walk through Lisbon, no talking" to "Slow Cities",
            "Sourdough, the lazy way" to "Kitchen Notes", "How a relay works, drawn by hand" to "Whiteboard", "Six hours of rain on a tin roof" to "Ambient",
            "Fixing a 40-year-old radio" to "Bench Repairs")
        return titles.mapIndexed { i, (t, c) ->
            PlaceCard("fake$i", t, c, "https://picsum.photos/seed/cosign$i/640/360", origin, listOf(754, 1835, 422, 963, 21600, 1288)[i], null, label)
        }
    }
}

/** Debug builds only: which place feeds to use ("fake" for the stand-in). */
object Places { @Volatile var fake = false }
