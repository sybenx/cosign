package cc.aaro.cosign

import android.content.Context
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.Policy
import java.io.File

/**
 * The latest version of each of your lists (follows, profile, relays, bookmarks…) that
 * this phone has seen signed under your key, so it can judge a change itself. Only
 * events with a valid signature count: a server can't make one up on its own.
 */
class Lists(context: Context) {
    private val file = File(context.filesDir, "lists.json")
    private val latest = HashMap<String, Event>()

    init {
        try {
            (Json.parse(file.readText()) as? List<*>)?.mapNotNull { Event.fromMap(it) }?.forEach { latest[Policy.keyOf(it)] = it }
        } catch (_: Exception) { /* nothing yet */ }
    }

    @Synchronized fun latest(key: String): Event? = latest[key]

    /** Keep it if it's yours, signed, and newer than what's here. */
    @Synchronized fun record(e: Event, groupX: String): Boolean {
        if (e.pubkey != groupX || e.kind !in Policy.ARCHIVED || !e.verify()) return false
        val key = Policy.keyOf(e)
        val have = latest[key]
        if (have != null && (have.createdAt > e.createdAt || have.id == e.id)) return false
        latest[key] = e
        file.writeText(Json.stringify(latest.values.map { it.toMap() }))
        return true
    }

    @Synchronized fun clear() { latest.clear(); file.delete() }
}
