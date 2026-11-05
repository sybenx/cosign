// What an app checks member-key signatures against (core 14.19 §5.9), as the TS reference's
// device/members.ts: the current device member keys, a durable log of removals that gets the post-redeal
// state hash once that redeal is in, a callback, and F5's flagged keys.
package keykin

import org.json.JSONArray
import org.json.JSONObject

class Members {
    data class Removed(val seq: Long, val key: String, val why: String, val change: String?, val state: String?) {
        fun json(): JSONObject = JSONObject().put("seq", seq).put("key", key).put("why", why).put("change", change ?: JSONObject.NULL).put("state", state ?: JSONObject.NULL)
    }
    data class DeviceKey(val key: String, val addedBy: String?, val flagged: Boolean)
    /** One new or updated entry, or a newly flagged key. */
    sealed class Event { data class Entry(val e: Removed) : Event(); data class Flagged(val key: String) : Event() }

    private val log = ArrayList<Removed>()
    private val kept = HashSet<String>()
    private val flagsTold = HashSet<String>()
    private var seq = 0L
    private var started = false
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<(Event) -> Unit>()
    private var last: Triple<String, String, List<DeviceKey>>? = null

    private fun addedBy(v: MembershipView): Map<String, String?> {
        val out = LinkedHashMap<String, String?>()
        v.recordDevices.forEach { out[it] = null }
        v.adds.forEach { out[it.key] = it.approver }
        return out
    }
    private fun keys(v: MembershipView): List<DeviceKey> {
        val by = addedBy(v); val removed = v.removed.toSet()
        return v.devices.filter { it !in removed }.sorted().map { k -> val a = by[k]; DeviceKey(k, a, a != null && a in removed && k !in kept) }
    }

    @Synchronized fun devices(): Triple<String, String, List<DeviceKey>> = last ?: refuse("no_view")
    @Synchronized fun removed(since: Long = 0): List<Removed> = log.filter { it.seq > since }
    fun onRemoved(cb: (Event) -> Unit): () -> Unit { listeners += cb; return { listeners -= cb } }
    @Synchronized fun keep(key: String) { kept += key; seen?.let { (s, v, ids) -> last = Triple(s, Codes.stateHash(ids.toList()), keys(v)) } }
    private var seen: Triple<String, MembershipView, Set<String>>? = null

    private fun tell(e: Event) { if (!started) return; for (cb in listeners) try { cb(e) } catch (_: Exception) {} }

    /** Bring the log up to date with this device's view and state (on every change set or state change). */
    @Synchronized fun update(self: String, v: MembershipView, ids: Set<String>) {
        val by = addedBy(v)
        for (k in v.removed.filter { it in by }.sorted()) {
            val rm = v.removes.firstOrNull { it.key == k }
            var i = log.indexOfFirst { it.key == k }
            if (i < 0) {
                // A remove change (`self` when the device approved its own), or §3.2's conflicting adds (void).
                val why = if (rm == null) "void" else if (rm.self) "self" else "remove"
                log += Removed(++seq, k, why, rm?.changeId ?: v.adds.firstOrNull { it.key == k }?.changeId, null)
                i = log.size - 1; tell(Event.Entry(log[i]))
            }
            val e = log[i]
            if (e.state == null) {
                // The post-redeal hash, once that change's redeal is in this device's state; a void has no redeal.
                val redeals = if (rm == null) emptyList() else v.redeals.values.filter { it.listHash == rm.listHash }.map { it.r.getString("id") }
                if (e.why == "void" || redeals.any { it in ids }) { log[i] = e.copy(seq = ++seq, state = Codes.stateHash(ids.toList())); tell(Event.Entry(log[i])) }
            }
        }
        seen = Triple(self, v, ids)
        val ks = keys(v)
        last = Triple(self, Codes.stateHash(ids.toList()), ks)
        for (k in ks.filter { it.flagged }) if (flagsTold.add(k.key)) tell(Event.Flagged(k.key))
        // What happened before this device's first view is in the log, but told to nobody: history, not news.
        started = true
    }

    @Synchronized fun dump(): JSONObject = JSONObject().put("log", JSONArray(log.map { it.json() })).put("kept", JSONArray(kept.sorted())).put("seq", seq).put("told", JSONArray(flagsTold.sorted()))
    @Synchronized fun load(x: JSONObject?) {
        if (x == null) return
        log.clear(); x.optJSONArray("log")?.let { a -> for (k in 0 until a.length()) { val o = a.getJSONObject(k)
            log += Removed(o.getLong("seq"), o.getString("key"), o.getString("why"), if (o.isNull("change")) null else o.getString("change"), if (o.isNull("state")) null else o.getString("state")) } }
        kept.clear(); x.optJSONArray("kept")?.let { a -> for (k in 0 until a.length()) kept += a.getString(k) }
        flagsTold.clear(); x.optJSONArray("told")?.let { a -> for (k in 0 until a.length()) flagsTold += a.getString(k) }
        seq = x.optLong("seq", 0); started = true
    }
}
