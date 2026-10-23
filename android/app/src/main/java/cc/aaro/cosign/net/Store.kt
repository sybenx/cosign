package cc.aaro.cosign.net

import cc.aaro.cosign.core.FAILED_SESSIONS_BEFORE_WARNING
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.PairingUri
import cc.aaro.cosign.core.THROTTLE_SECONDS
import cc.aaro.cosign.core.TransferRecord

// What a device remembers between sessions (§9.3, §11.3a, §14): relays that worked,
// burners a code failed against, failed sessions, and the transfer log. Nothing here
// is secret. A port of src/web/store.ts, minus NIP-66 discovery.

interface KeyValue {
    fun get(key: String): String?
    fun put(key: String, value: String)
}

class MemoryKeyValue : KeyValue {
    private val map = HashMap<String, String>()
    override fun get(key: String) = map[key]
    override fun put(key: String, value: String) { map[key] = value }
}

/** syb.lol (Ditto, the maintainer's relay) passes the loopback test for kind 21059 wraps. */
val DEFAULT_RELAYS = listOf("wss://syb.lol")

enum class Source { CONFIGURED, REMEMBERED, LEARNED, SEED }

data class LoggedTransfer(val record: TransferRecord, val transport: String, val relays: List<String>)

class Store(private val kv: KeyValue, private val now: () -> Long = { System.currentTimeMillis() / 1000 }) {
    private val lock = Any()

    private fun readMap(key: String): MutableMap<String, Any?> =
        ((kv.get(key)?.let { Json.parse(it) } as? Map<*, *>)?.entries?.associate { it.key as String to it.value } ?: emptyMap()).toMutableMap()

    private fun readList(key: String): MutableList<Any?> =
        ((kv.get(key)?.let { Json.parse(it) } as? List<*>) ?: emptyList<Any?>()).toMutableList()

    // ---- relays --------------------------------------------------------------------------

    /** Until the user sets their own, the app's own relay is tried first. */
    fun configured(): List<String> = synchronized(lock) {
        if (kv.get("configured") == null) DEFAULT_RELAYS else readList("configured").filterIsInstance<String>()
    }

    fun setConfigured(urls: List<String>) = synchronized(lock) {
        kv.put("configured", Json.stringify(urls.mapNotNull { PairingUri.normalizeRelayUrl(it) }.distinct()))
    }

    /** Relays that passed here before, most recently first. */
    fun remembered(): List<String> = synchronized(lock) {
        readMap("relays").entries.sortedByDescending { ((it.value as? Map<*, *>)?.get("ok") as? Long) ?: 0L }.map { it.key }
    }

    fun learned(): List<String> = synchronized(lock) { readList("learned").filterIsInstance<String>() }

    fun notePassed(url: String) = synchronized(lock) {
        val relays = readMap("relays")
        relays[url] = mapOf("ok" to now(), "fails" to 0L)
        kv.put("relays", Json.stringify(relays))
    }

    /** A relay that keeps failing is forgotten unless the user put it there (§11.3a). */
    fun noteFailed(url: String) = synchronized(lock) {
        val relays = readMap("relays")
        val memo = relays[url] as? Map<*, *> ?: return@synchronized
        val fails = ((memo["fails"] as? Long) ?: 0L) + 1
        if (fails >= 5) relays.remove(url) else relays[url] = mapOf("ok" to memo["ok"], "fails" to fails)
        kv.put("relays", Json.stringify(relays))
    }

    /** Relays named in a code this device scanned, in a session that completed. Never private ones. */
    fun noteLearned(urls: List<String>) = synchronized(lock) {
        val public = urls.filter { url -> runCatching { !PairingUri.isPrivateHost(java.net.URI(url).host) }.getOrDefault(false) }
        val list = (public + learned()).distinct().take(16)
        kv.put("learned", Json.stringify(list))
    }

    /** A relay that answered "rate-limited" is not tested again for ten minutes. */
    fun noteRateLimited(url: String) = synchronized(lock) {
        val resting = readMap("resting").filterValues { (it as? Long ?: 0L) > now() }.toMutableMap()
        resting[url] = now() + 600
        kv.put("resting", Json.stringify(resting))
    }

    fun isResting(url: String): Boolean = synchronized(lock) { (readMap("resting")[url] as? Long ?: 0L) > now() }

    // ---- §9.3 throttle --------------------------------------------------------------------

    fun isBlocked(pub: String): Boolean = synchronized(lock) {
        val t = readMap("blocked")[pub] as? Long ?: return@synchronized false
        now() - t < THROTTLE_SECONDS
    }

    fun noteFailedSession(pubs: List<String>) = synchronized(lock) {
        val blocked = readMap("blocked").filterValues { (it as? Long)?.let { t -> now() - t < THROTTLE_SECONDS } == true }.toMutableMap()
        for (p in pubs) blocked[p] = now()
        kv.put("blocked", Json.stringify(blocked))
        val sessions = readList("failedSessions").filterIsInstance<Long>().filter { now() - it < THROTTLE_SECONDS } + now()
        kv.put("failedSessions", Json.stringify(sessions))
    }

    /** After three failed sessions within an hour the user is told it may be interference (§9.3). */
    fun shouldWarn(): Boolean = synchronized(lock) {
        readList("failedSessions").filterIsInstance<Long>().count { now() - it < THROTTLE_SECONDS } >= FAILED_SESSIONS_BEFORE_WARNING
    }

    fun acknowledgeWarning() = synchronized(lock) { kv.put("failedSessions", "[]") }

    // ---- §14 record -----------------------------------------------------------------------

    /** A later record for the same peer replaces an earlier one. */
    fun addRecord(entry: LoggedTransfer) = synchronized(lock) {
        val r = entry.record
        val item = mapOf(
            "ts" to r.ts, "profile" to r.profile, "role" to r.role.name.lowercase(), "outcome" to r.outcome.wire,
            "sas" to r.sas, "peer" to r.peer, "multi" to r.multi, "check" to r.check.wire,
            "transport" to entry.transport, "relays" to entry.relays,
        )
        val list = readList("records").filter { (it as? Map<*, *>)?.get("peer") != r.peer }.toMutableList()
        list.add(0, item)
        kv.put("records", Json.stringify(list.take(200)))
    }

    fun records(): List<Map<*, *>> = synchronized(lock) { readList("records").filterIsInstance<Map<*, *>>() }
}
