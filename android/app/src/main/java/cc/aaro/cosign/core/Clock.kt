package cc.aaro.cosign.core

import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * The time, as the network tells it, not as this phone's clock says (server/clock.ts is
 * the same). A phone set ahead, by mistake or on purpose, would otherwise let something
 * dated in the future look like now. The Date header of a few well-known HTTPS sites
 * can't be forged without breaking TLS; their median sets the offset.
 */
object Clock {
    private val SOURCES = listOf("https://cloudflare.com", "https://www.google.com", "https://cosign.aaro.cc", "https://github.com")
    private val http = OkHttpClient.Builder().callTimeout(5, TimeUnit.SECONDS).followRedirects(false).build()
    @Volatile private var offset = 0L

    /** Seconds since 1970, by the network's clock when it has answered, else this phone's. */
    fun now(): Long = System.currentTimeMillis() / 1000 + offset

    /** Ask the network. Blocks for a few seconds; call off the main thread. */
    fun check(): Long? {
        val got = SOURCES.mapNotNull { url ->
            try {
                val t0 = System.currentTimeMillis()
                http.newCall(Request.Builder().url(url).head().build()).execute().use { r ->
                    val date = r.headers.getDate("Date") ?: return@mapNotNull null
                    date.time / 1000.0 - (t0 + System.currentTimeMillis()) / 2000.0
                }
            } catch (_: Exception) { null }
        }.sorted()
        if (got.size < 2 || got.last() - got.first() > 120) return null // too few, or they disagree: keep what we had
        offset = Math.round(got[got.size / 2])
        return offset
    }
}
