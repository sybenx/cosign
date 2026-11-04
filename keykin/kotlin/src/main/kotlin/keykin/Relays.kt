// Doors §2's counted relays, as the TS reference's device/relays.ts: the account's recorded relays, leaving out one
// that failed 10 tries over at least 7 days while other counted relays answered, or refused with blocked: or
// restricted: on three tries over at least 12 hours; a dropped relay is retried weekly and counts again once it
// answers; one that refuses writes but answers reads counts only for fetches.
package keykin

import org.json.JSONArray
import org.json.JSONObject

class RelayHealth {
    companion object { private const val FAILS = 10; private const val FAIL_SPAN_S = 7 * 86400L; private const val REFUSALS = 3; private const val REFUSAL_SPAN_S = 12 * 3600L; private const val RETRY_S = 7 * 86400L
        /** More than half of `set` among `answered` (an empty set never has a majority). */
        fun majority(answered: Collection<String>, set: List<String>): Boolean { val a = answered.toSet(); return set.isNotEmpty() && set.count { it in a } * 2 > set.size } }
    private class H(val fails: ArrayList<Long> = ArrayList(), val refusals: ArrayList<Long> = ArrayList(), var dropped: Long? = null, var writeRefused: Boolean = false)
    private val h = LinkedHashMap<String, H>()
    private fun of(u: String) = h.getOrPut(u) { H() }
    @Synchronized fun counted(recorded: List<String>): List<String> = recorded.distinct().filter { h[it]?.dropped == null }
    @Synchronized fun writable(recorded: List<String>): List<String> = counted(recorded).filter { h[it]?.writeRefused != true }
    @Synchronized fun toFetch(recorded: List<String>, now: Long): List<String> = recorded.distinct().filter { val d = h[it]?.dropped; d == null || now - d >= RETRY_S }
    @Synchronized fun fetched(asked: List<String>, answered: List<String>, recorded: List<String>, now: Long) {
        val ok = answered.toSet(); val counted = counted(recorded).toSet()
        for (u in asked) {
            val x = of(u)
            if (u in ok) { x.fails.clear(); x.refusals.clear(); x.dropped = null; continue }
            if (x.dropped != null) { x.dropped = now; continue }
            if (answered.none { it != u && it in counted }) continue
            x.fails += now; if (x.fails.size > FAILS) x.fails.removeAt(0)
            if (x.fails.size >= FAILS && now - x.fails[0] >= FAIL_SPAN_S) x.dropped = now
        }
    }
    @Synchronized fun published(results: Map<String, Any>, now: Long) {
        for ((u, r) in results) {
            val x = of(u)
            if (r == true) { x.refusals.clear(); x.writeRefused = false; continue }
            val s = r.toString(); if (s == "down") continue
            if (Regex("^(blocked|restricted):").containsMatchIn(s)) {
                x.refusals += now; if (x.refusals.size > REFUSALS) x.refusals.removeAt(0)
                if (x.refusals.size >= REFUSALS && now - x.refusals[0] >= REFUSAL_SPAN_S) x.dropped = now
            } else if (!Regex("too large|size|big", RegexOption.IGNORE_CASE).containsMatchIn(s)) x.writeRefused = true
        }
    }
    @Synchronized fun dump(): JSONArray = JSONArray(h.map { (u, x) -> JSONArray(listOf(u, JSONObject().put("fails", JSONArray(x.fails)).put("refusals", JSONArray(x.refusals)).put("dropped", x.dropped ?: JSONObject.NULL).put("writeRefused", x.writeRefused))) })
    @Synchronized fun load(a: JSONArray?) {
        h.clear(); if (a == null) return
        for (i in 0 until a.length()) (a.opt(i) as? JSONArray)?.let { p -> val o = p.optJSONObject(1) ?: return@let
            fun longs(n: String) = o.optJSONArray(n)?.let { l -> (0 until l.length()).map { l.getLong(it) } } ?: emptyList()
            h[p.getString(0)] = H(ArrayList(longs("fails")), ArrayList(longs("refusals")), (o.opt("dropped") as? Number)?.toLong(), o.optBoolean("writeRefused")) }
    }
    @Synchronized fun clear() = h.clear()
}
