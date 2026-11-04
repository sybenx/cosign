// Doors §2's counted relays, as the TS reference's device/relays.ts: the account's recorded relays, leaving out one
// that failed 10 tries over at least 7 days while other counted relays answered; one that refused writes with
// blocked: or restricted: on three tries over at least 12 hours counts only for fetches. A left-out relay is
// retried weekly. Failures and refusals count from the first since the relay last answered (review 19 H3); a
// timeout or any other passing refusal never counts against a relay (H4), and duplicate: is an OK.
package keykin

import org.json.JSONArray
import org.json.JSONObject

class RelayHealth {
    companion object { private const val FAILS = 10; private const val FAIL_SPAN_S = 7 * 86400L; private const val REFUSALS = 3; private const val REFUSAL_SPAN_S = 12 * 3600L; private const val RETRY_S = 7 * 86400L
        /** More than half of `set` among `answered` (an empty set never has a majority). */
        fun majority(answered: Collection<String>, set: List<String>): Boolean { val a = answered.toSet(); return set.isNotEmpty() && set.count { it in a } * 2 > set.size } }
    private class H(var fails: Int = 0, var firstFail: Long? = null, var refusals: Int = 0, var firstRefusal: Long? = null, var dropped: Long? = null, var writeRefused: Long? = null)
    private val h = LinkedHashMap<String, H>()
    private fun of(u: String) = h.getOrPut(u) { H() }
    @Synchronized fun counted(recorded: List<String>): List<String> = recorded.distinct().filter { h[it]?.dropped == null }
    /** What a publish writes to: the counted relays, a fetch-only one only on its weekly retry. */
    @Synchronized fun writable(recorded: List<String>, now: Long = Long.MAX_VALUE): List<String> = counted(recorded).filter { val w = h[it]?.writeRefused; w == null || now - w >= RETRY_S }
    @Synchronized fun toFetch(recorded: List<String>, now: Long): List<String> = recorded.distinct().filter { val d = h[it]?.dropped; d == null || now - d >= RETRY_S }
    @Synchronized fun fetched(asked: List<String>, answered: List<String>, recorded: List<String>, now: Long) {
        val ok = answered.toSet(); val counted = counted(recorded).toSet()
        for (u in asked) {
            val x = of(u)
            if (u in ok) { x.fails = 0; x.firstFail = null; x.dropped = null; continue }
            if (x.dropped != null) { x.dropped = now; continue }
            if (answered.none { it != u && it in counted }) continue
            x.fails++; if (x.firstFail == null) x.firstFail = now
            if (x.fails >= FAILS && now - x.firstFail!! >= FAIL_SPAN_S) x.dropped = now
        }
    }
    @Synchronized fun published(results: Map<String, Any>, now: Long) {
        for ((u, r) in results) {
            val x = of(u)
            if (r == true || r.toString().startsWith("duplicate:")) { x.refusals = 0; x.firstRefusal = null; x.writeRefused = null; continue }
            if (!Regex("^(blocked|restricted):").containsMatchIn(r.toString())) continue
            if (x.writeRefused != null) { x.writeRefused = now; continue }
            x.refusals++; if (x.firstRefusal == null) x.firstRefusal = now
            if (x.refusals >= REFUSALS && now - x.firstRefusal!! >= REFUSAL_SPAN_S) x.writeRefused = now
        }
    }
    @Synchronized fun dump(): JSONArray = JSONArray(h.map { (u, x) -> JSONArray(listOf(u, JSONObject().put("fails", x.fails).put("firstFail", x.firstFail ?: JSONObject.NULL).put("refusals", x.refusals)
        .put("firstRefusal", x.firstRefusal ?: JSONObject.NULL).put("dropped", x.dropped ?: JSONObject.NULL).put("writeRefused", x.writeRefused ?: JSONObject.NULL))) })
    @Synchronized fun load(a: JSONArray?) {
        h.clear(); if (a == null) return
        fun l(o: JSONObject, n: String) = (o.opt(n) as? Number)?.toLong()
        for (i in 0 until a.length()) (a.opt(i) as? JSONArray)?.let { p -> val o = p.optJSONObject(1) ?: return@let
            if (o.opt("fails") !is Number) return@let
            h[p.getString(0)] = H(o.getInt("fails"), l(o, "firstFail"), o.optInt("refusals"), l(o, "firstRefusal"), l(o, "dropped"), l(o, "writeRefused")) }
    }
    @Synchronized fun clear() = h.clear()
}
