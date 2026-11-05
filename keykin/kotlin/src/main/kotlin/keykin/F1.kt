// When a device counts a seated server as dead and shows the F1 card (core §6.7.6 F1, §6.7.7; Server profile §4.1,
// §5), as the TS reference's src/f1.ts: it has been quiet for 7 days; or a live answer to `notice_get` carries a
// shutdown date no more than 30 days ahead; or, for a day, it has answered `deleted` (one that doesn't verify) or
// "unknown account" while its peers still serve the account. A pushed notice only prompts a `notice_get`. A server
// that answers but won't co-sign is F4's case, never F1. Pure: the device feeds it what each server answered.
package keykin

import org.json.JSONArray
import org.json.JSONObject

class F1Watch(private val g: String) {
    companion object {
        const val QUIET_S = 7 * 86400L; const val DENIAL_S = 86400L; const val NOTICE_AHEAD_S = 30 * 86400L
        const val NOTICE_ASK_S = 3600L; const val NOTICE_ANSWER_S = 120L + 30
        fun noticeDigest(g: String, shutdown: Long?, seq: Long, host: String, member: String): ByteArray =
            Approvals.detached("shutdown", g, JSONObject().put("shutdown", shutdown ?: JSONObject.NULL).put("seq", seq).put("host", host).put("member", member))
        fun answerDigest(g: String, shutdown: Long?, seq: Long, host: String, member: String, re: String): ByteArray =
            Approvals.detached("shutdown-answer", g, JSONObject().put("shutdown", shutdown ?: JSONObject.NULL).put("seq", seq).put("host", host).put("member", member).put("re", re))
    }
    class Kept(val seq: Long, val at: Long?)
    class Asking(val id: String, val until: Long, var best: Kept?)
    class Watch(var seatedAt: Long, var lastHeard: Long, var lastServing: Long?, var deniedSince: Long?, var seat: String, var kept: Kept?, var asking: Asking?, var askedAt: Long?)
    private val s = LinkedHashMap<String, Watch>()

    /** A seated server: its host and the member key of its seat. A new member key for a host is a new seat. */
    @Synchronized fun seat(host: String, seatKey: String, now: Long) {
        val w = s[host]
        if (w != null) { if (w.seat != seatKey) { w.seat = seatKey; w.kept = null; w.asking = null }; return }
        s[host] = Watch(now, now, null, null, seatKey, null, null, null)
    }
    @Synchronized fun forget(host: String) { s.remove(host) }
    /** What `host` answered at `now`: "serving", "silent" or "denied" (a denial is an answer too). */
    @Synchronized fun saw(host: String, seen: String, now: Long) {
        val w = s[host] ?: return
        when (seen) {
            "serving" -> { w.lastServing = now; w.lastHeard = now; w.deniedSince = null }
            "denied" -> { w.lastHeard = now; if (w.deniedSince == null) w.deniedSince = now }
        }
    }
    private fun shape(n: JSONObject) = n.opt("host") is String && n.opt("member") is String && (n.opt("seq") as? Number)?.toLong()?.let { it >= 0 } == true &&
        (n.isNull("shutdown") || n.opt("shutdown") is Number)
    private fun shutdownOf(n: JSONObject): Long? = if (n.isNull("shutdown")) null else (n.get("shutdown") as Number).toLong()
    /** A pushed notice (no `re`): true when the device should send `notice_get` now (signed by that host for that
     *  seat's member key, a `seq` above the one kept, at most once an hour per seat). */
    @Synchronized fun pushed(n: JSONObject, now: Long): Boolean {
        if (!shape(n) || n.has("re")) return false
        val w = s[n.getString("host")] ?: return false
        if (w.seat != n.getString("member") || !schnorrVerify(n.optString("host_sig"), noticeDigest(g, shutdownOf(n), n.getLong("seq"), n.getString("host"), n.getString("member")), n.getString("host"))) return false
        if (w.kept != null && n.getLong("seq") <= w.kept!!.seq) return false
        return w.askedAt == null || now - w.askedAt!! >= NOTICE_ASK_S
    }
    @Synchronized fun asked(host: String, id: String, now: Long) { val w = s[host] ?: return; w.asking = Asking(id, now + NOTICE_ANSWER_S, null); w.askedAt = now }
    /** A live answer, sealed by `from`: only for the outstanding request, from that seat's member key, signed. */
    @Synchronized fun answer(n: JSONObject, from: String, now: Long): Boolean {
        if (!shape(n) || n.opt("re") !is String) return false
        val w = s[n.getString("host")] ?: return false
        val a = w.asking ?: return false
        if (w.seat != from || n.getString("member") != from || a.id != n.getString("re") || now > a.until) return false
        if (!schnorrVerify(n.optString("host_sig"), answerDigest(g, shutdownOf(n), n.getLong("seq"), n.getString("host"), n.getString("member"), n.getString("re")), n.getString("host"))) return false
        if (a.best != null && a.best!!.seq >= n.getLong("seq")) return false
        a.best = Kept(n.getLong("seq"), shutdownOf(n)); w.kept = a.best
        return true
    }
    @Synchronized fun closing(host: String): Long? = s[host]?.kept?.at
    /** Why `host` counts as dead at `now` ("quiet", "shutdown", "denied"), or null. */
    @Synchronized fun dead(host: String, now: Long): String? {
        val w = s[host] ?: return null
        w.kept?.at?.let { if (it <= now + NOTICE_AHEAD_S) return "shutdown" }
        if (now - w.lastHeard >= QUIET_S) return "quiet"
        val d = w.deniedSince
        if (d != null && now - d >= DENIAL_S && s.any { (h, x) -> h != host && (x.lastServing ?: -1) >= d + DENIAL_S }) return "denied"
        return null
    }
    /** The card: which seats to move (F1 for one, F2 for two, F3 for all), each `{seat, host, why}`. */
    fun card(seats: List<Pair<String, String>>, now: Long): List<JSONObject> =
        seats.mapNotNull { (seat, host) -> dead(host, now)?.let { JSONObject().put("seat", seat).put("host", host).put("why", it) } }

    @Synchronized fun dump(): JSONArray = JSONArray(s.map { (h, w) -> JSONArray(listOf(h, JSONObject().put("seatedAt", w.seatedAt).put("lastHeard", w.lastHeard)
        .put("lastServing", w.lastServing ?: JSONObject.NULL).put("deniedSince", w.deniedSince ?: JSONObject.NULL).put("seat", w.seat)
        .put("kept", w.kept?.let { JSONObject().put("seq", it.seq).put("at", it.at ?: JSONObject.NULL) } ?: JSONObject.NULL).put("asking", JSONObject.NULL).put("askedAt", w.askedAt ?: JSONObject.NULL))) })
    @Synchronized fun load(a: JSONArray?) {
        s.clear(); if (a == null) return
        fun lo(o: JSONObject, k: String) = if (o.isNull(k)) null else o.optLong(k)
        for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> val o = p.optJSONObject(1) ?: return@let
            s[p.getString(0)] = Watch(o.optLong("seatedAt"), o.optLong("lastHeard"), lo(o, "lastServing"), lo(o, "deniedSince"), o.optString("seat"),
                o.optJSONObject("kept")?.let { k -> Kept(k.optLong("seq"), lo(k, "at")) }, null, lo(o, "askedAt")) }
    }
}
