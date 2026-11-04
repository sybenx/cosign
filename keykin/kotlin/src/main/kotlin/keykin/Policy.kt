// Device policy §1–§4 and §6, as the TS reference's device/history.ts and device/policy.ts: the device's own
// history (only the account's verified events), the records every device syncs in its metadata months (grant per
// event, deletions, removal and addition logs, pre-site and last-approved versions), the judge's rows, and the
// Guard that holds what the person sees (cards, the 10-second Undo, auto-declines) and serialises a site's deletions
// and list changes (review 18 M1).
//
// Not yet, as in TS: §5 (drafts staged offline); a co-signing device's `waited` statements; merging a leaving
// device's records; retention by whether an event is current (13 months, so a grant older than that gets a new
// pre-site version); batching NIP-98 deletes of file URLs into one card.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object Kinds {
    const val PROFILE = 0
    val RELAY_LISTS = setOf(10002, 10050)
    val FOLLOW_MUTE = setOf(3, 10000)
    val OTHER_LISTS = setOf(10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10013, 10015, 10020, 10030, 10063, 10101, 10102,
        30000, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30015, 30030, 39089)
    val WALLET = setOf(17375, 37375, 7375, 7376, 7374, 10019)
    fun judged(k: Int) = k == PROFILE || k in RELAY_LISTS || k in FOLLOW_MUTE || k in OTHER_LISTS || k in WALLET
    fun isList(k: Int) = k in RELAY_LISTS || k in FOLLOW_MUTE || k in OTHER_LISTS
    /** A replaceable or addressable event's address: kind, and `d` for addressable kinds. */
    fun addrOf(kind: Int, tags: List<List<String>>): String? = when {
        kind == 0 || kind == 3 || kind in 10000..19999 -> "$kind"
        kind in 30000..39999 -> "$kind:" + (tags.firstOrNull { it.isNotEmpty() && it[0] == "d" }?.getOrNull(1) ?: "")
        else -> null
    }
    /** An `a` value (`kind:pubkey:d`) as an address of the account's, or null if it names another key. */
    fun addrOfA(a: String, g: String): String? {
        val i = a.indexOf(':'); val j = if (i < 0) -1 else a.indexOf(':', i + 1)
        if (i < 0 || j < 0) return null
        val k = a.substring(0, i).toIntOrNull() ?: return null
        // Only a replaceable or addressable kind has an address (review 18 L4).
        if (k.toString() != a.substring(0, i) || a.substring(i + 1, j).lowercase() != g || !Rules.replaceable(k)) return null
        return if (k in 30000..39999) "$k:${a.substring(j + 1)}" else "$k"
    }
}

/** The device's own history of the account's events (§1). */
class History(private val g: () -> String) {
    companion object { private const val VERSIONS = 25; private const val SET_VERSIONS = 5; private const val OTHER_VERSIONS = 2; private const val MAX_ADDRS = 1000; private const val MAX_EVENTS = 3000
        private const val MAX_DELETED = 5000
        /** The history's size in bytes, at most (review 18 M9). */
        private const val MAX_BYTES = 4_000_000L
        private fun sizeOf(e: Event) = e.content.length + jsJson(e.tags).length + 200L
        private fun keepOf(k: Int) = if (k == Kinds.PROFILE || k in Kinds.RELAY_LISTS || k in Kinds.FOLLOW_MUTE) VERSIONS else if (Kinds.judged(k)) SET_VERSIONS else OTHER_VERSIONS }
    private var bytes = 0L
    val versions = LinkedHashMap<String, MutableList<Event>>()
    val events = LinkedHashMap<String, Event>()
    val pinned = LinkedHashMap<String, Event>()
    val deletedAt = HashMap<String, Long>()
    private fun addr(e: Event) = if (Rules.replaceable(e.kind)) Kinds.addrOf(e.kind, e.tags) else null

    /** Only the account's events whose signature verifies (live finding #8). */
    @Synchronized fun take(e: Event, checked: Boolean = false): Boolean {
        if (e.pubkey != g() || (!checked && !verifyEvent(e))) return false
        if (e.kind == 5) for (t in e.tags) if (t.size >= 2 && (t[0] == "e" || t[0] == "a")) {
            val k = if (t[0] == "e") t[1].lowercase() else Kinds.addrOfA(t[1], g()); if (k != null) deletedAt[k] = maxOf(deletedAt[k] ?: 0, e.createdAt)
            while (deletedAt.size > MAX_DELETED) deletedAt.remove(deletedAt.keys.first())
        }
        val a = addr(e)
        if (a == null) { if (e.id !in events) { events[e.id] = e; bytes += sizeOf(e); while (events.size > MAX_EVENTS) bytes -= sizeOf(events.remove(events.keys.first())!!) }; fit(); return true }
        val vs = versions.remove(a) ?: ArrayList()
        if (vs.none { it.id == e.id }) { vs += e; bytes += sizeOf(e); vs.sortWith(compareBy<Event>({ it.createdAt }, { it.id })) }
        while (vs.size > keepOf(e.kind)) bytes -= sizeOf(vs.removeAt(0))
        versions[a] = vs
        while (versions.size > MAX_ADDRS) versions.remove(versions.keys.first())!!.forEach { bytes -= sizeOf(it) }
        fit()
        return true
    }
    /** Over the byte cap: the oldest regular events, then the oldest non-current versions, go first. */
    private fun fit() {
        while (bytes > MAX_BYTES && events.isNotEmpty()) bytes -= sizeOf(events.remove(events.keys.first())!!)
        for (vs in versions.values) { if (bytes <= MAX_BYTES) break; while (vs.size > 1 && bytes > MAX_BYTES) bytes -= sizeOf(vs.removeAt(0)) }
    }
    @Synchronized fun all(a: String): List<Event> {
        val m = LinkedHashMap<String, Event>()
        for (v in versions[a] ?: emptyList<Event>()) m[v.id] = v
        for (p in pinned.values) if (addr(p) == a) m[p.id] = p
        return m.values.sortedBy { it.createdAt }
    }
    /** The newest version known at an address (relays break ties on the lowest id). */
    @Synchronized fun current(a: String): Event? = all(a).fold(null as Event?) { b, v -> if (b == null || v.createdAt > b.createdAt || (v.createdAt == b.createdAt && v.id < b.id)) v else b }
    /** The newest version dated at or before `t`, or else the oldest known. */
    @Synchronized fun at(a: String, t: Long): Event? { val vs = all(a); return vs.lastOrNull { it.createdAt <= t } ?: vs.firstOrNull() }
    @Synchronized fun get(id: String): Event? { val lc = id.lowercase(); return events[lc] ?: pinned[lc] ?: versions.values.flatten().firstOrNull { it.id == lc } }
    @Synchronized fun pin(e: Event) { pinned[e.id] = e }
    @Synchronized fun dump(): JSONObject = JSONObject()
        .put("versions", JSONArray(versions.map { (a, vs) -> JSONArray(listOf(a, JSONArray(vs.map { it.json() }))) }))
        .put("events", JSONArray(events.values.map { it.json() })).put("pinned", JSONArray(pinned.values.map { it.json() }))
        .put("deletedAt", JSONArray(deletedAt.map { (k, v) -> JSONArray(listOf(k, v)) }))
    @Synchronized fun load(x: JSONObject?) {
        clear(); if (x == null) return
        fun evs(a: JSONArray?) = (0 until (a?.length() ?: 0)).mapNotNull { a!!.optJSONObject(it)?.let(Event::of)?.takeIf { e -> e.kind >= 0 } }
        x.optJSONArray("versions")?.let { a -> for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> versions[p.getString(0)] = evs(p.optJSONArray(1)).toMutableList() } }
        for (e in evs(x.optJSONArray("events"))) events[e.id] = e
        for (e in evs(x.optJSONArray("pinned"))) pinned[e.id] = e
        x.optJSONArray("deletedAt")?.let { a -> for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> deletedAt[p.getString(0)] = p.getLong(1) } }
        bytes = (events.values + versions.values.flatten()).sumOf { sizeOf(it) }
    }
    @Synchronized fun clear() { versions.clear(); events.clear(); pinned.clear(); deletedAt.clear(); bytes = 0 }
}

/** A deletion a grant (or the member app) got signed. */
data class Del(val at: Long, val owner: String, val n: Int, val single: Boolean, val wallet: Boolean, val approved: Boolean)

/** §1's records, synced in the metadata months alongside Doors §1's evidence (TS `Ledger`). */
class Ledger {
    companion object { private const val PER_OWNER = 2000; private const val DEL_KEEP_S = 2 * 86400L; private const val MAX_DELS = 5000; private val HEX = Regex("^[0-9a-f]{64}$")
        /** Log entries per owner and month, across all its lists (review 18 H1): past it a site's removals each ask. */
        const val LOG_PER_OWNER = 2000
        private fun k2(owner: String, list: String) = "$owner\u0000$list"
        private fun split(k: String) = k.indexOf('\u0000').let { listOf(k.substring(0, it), k.substring(it + 1)) } }
    val signed = LinkedHashMap<String, String>()
    val dels = ArrayList<Del>()
    val removed = LinkedHashMap<String, LinkedHashMap<String, Long>>()
    val added = LinkedHashMap<String, LinkedHashMap<String, Long>>()
    val presite = LinkedHashMap<String, String>()
    val approved = LinkedHashMap<String, Pair<String, Long>>()

    fun sign(id: String, owner: String) { if (id !in signed && signed.values.count { it == owner } < PER_OWNER) signed[id] = owner }
    fun del(d: Del) { dels += d; if (dels.size > MAX_DELS) prune(d.at); if (dels.size > MAX_DELS) dels.removeAt(0) }
    fun log(which: String, owner: String, list: String, items: Iterable<String>, at: Long) {
        val m = if (which == "removed") removed else added
        val s = m[k2(owner, list)] ?: LinkedHashMap()
        var n = logCount(which, owner)
        for (it in items) { if (it in s) { s[it] = at; continue }; if (n >= LOG_PER_OWNER) break; s[it] = at; n++ }
        if (s.isNotEmpty()) m[k2(owner, list)] = s
    }
    /** How many entries an owner has in a log, across its lists. */
    fun logCount(which: String, owner: String) = (if (which == "removed") removed else added).entries.filter { split(it.key)[0] == owner }.sumOf { it.value.size }
    fun removals(owner: String, list: String): Map<String, Long> = removed[k2(owner, list)] ?: emptyMap()
    fun additions(owner: String, list: String): Map<String, Long> = added[k2(owner, list)] ?: emptyMap()
    fun presiteOf(owner: String, list: String) = presite[k2(owner, list)]
    fun setPresite(owner: String, list: String, id: String) { presite.putIfAbsent(k2(owner, list), id) }
    fun approvedOf(owner: String, list: String) = approved[k2(owner, list)]
    fun approve(owner: String, list: String, id: String, at: Long) { val k = k2(owner, list); val p = approved[k]; if (p == null || p.second <= at) approved[k] = id to at }
    fun listsOf(owner: String): List<String> = (removed.keys + added.keys).map(::split).filter { it[0] == owner }.map { it[1] }.distinct()
    /** Deletion targets in the last 10 minutes without an approval, from every owner (the core's burst). */
    fun burst(now: Long) = dels.filter { !it.approved && now - it.at < 600 }.sumOf { it.n }
    fun prune(now: Long) { dels.removeAll { now - it.at >= DEL_KEEP_S } }
    fun size() = signed.size + dels.size + removed.values.sumOf { it.size } + added.values.sumOf { it.size } + presite.size + approved.size
    /** When a month must fit its parts: never what makes judging stricter (removal logs, the last 2 days' deletions,
     *  pre-site and approved versions, review 18 H1); expired deletions, then additions, then the oldest attributions. */
    fun trim(n: Int, now: Long = dels.maxOfOrNull { it.at } ?: 0) {
        val before = size(); prune(now)
        var left = n - (before - size())
        for ((_, s) in added) { if (left <= 0) break; for (it in s.keys.take(left).toList()) { s.remove(it); left-- } }
        added.entries.removeIf { it.value.isEmpty() }
        for (k in signed.keys.take(maxOf(0, left)).toList()) { signed.remove(k); left-- }
    }
    /** The last resort for a month that still won't fit: the oldest log entries and deletions. */
    fun trimLogs(n: Int) {
        repeat(minOf(n, dels.size)) { dels.removeAt(0) }
        for ((_, s) in removed) s.keys.take(n).toList().forEach { s.remove(it) }; removed.entries.removeIf { it.value.isEmpty() }
        presite.keys.take(n).toList().forEach { presite.remove(it) }; approved.keys.take(n).toList().forEach { approved.remove(it) }
    }
    /** As published: plain arrays, in TS's order. */
    fun data(): JSONObject = JSONObject()
        .put("signed", JSONArray(signed.map { (id, o) -> JSONArray(listOf(id, o)) }))
        .put("dels", JSONArray(dels.map { JSONArray(listOf(it.at, it.owner, it.n, (if (it.single) 1 else 0) or (if (it.wallet) 2 else 0) or (if (it.approved) 4 else 0))) }))
        .put("removed", JSONArray(removed.flatMap { (k, s) -> s.map { (it, at) -> JSONArray(split(k) + listOf(it, at)) } }))
        .put("added", JSONArray(added.flatMap { (k, s) -> s.map { (it, at) -> JSONArray(split(k) + listOf(it, at)) } }))
        .put("presite", JSONArray(presite.map { (k, id) -> JSONArray(split(k) + listOf(id)) }))
        .put("approved", JSONArray(approved.map { (k, p) -> JSONArray(split(k) + listOf(p.first, p.second)) }))
    /** Merge published records in; `mine` says which owners the maker may write, and a malformed entry costs only itself. */
    fun take(x: JSONObject?, mine: (Any?) -> Boolean) {
        if (x == null) return
        fun rows(n: String) = x.optJSONArray(n)?.let { a -> (0 until a.length()).mapNotNull { a.opt(it) as? JSONArray } } ?: emptyList()
        fun str(v: Any?) = v is String && v.length <= 1024
        fun int(v: Any?): Long? = when (v) { is Int -> v.toLong(); is Long -> v; else -> null }?.takeIf { it >= 0 && it <= 9007199254740991L }
        for (r in rows("signed")) { val id = r.opt(0); if (id is String && HEX.matches(id) && mine(r.opt(1))) signed[id] = r.opt(1) as String }
        for (r in rows("dels")) { val at = int(r.opt(0)); val n = int(r.opt(2)); val f = int(r.opt(3))
            if (at != null && mine(r.opt(1)) && n != null && n <= Int.MAX_VALUE && f != null) dels += Del(at, r.opt(1) as String, n.toInt(), f and 1L != 0L, f and 2L != 0L, f and 4L != 0L) }
        for (w in listOf("removed", "added")) for (r in rows(w)) { val at = int(r.opt(3))
            if (mine(r.opt(0)) && str(r.opt(1)) && str(r.opt(2)) && at != null) {
                val m = if (w == "removed") removed else added; val k = k2(r.opt(0) as String, r.opt(1) as String); val s = m[k] ?: LinkedHashMap()
                s[r.opt(2) as String] = maxOf(s[r.opt(2) as String] ?: 0, at); m[k] = s } }
        for (r in rows("presite")) { val id = r.opt(2); if (mine(r.opt(0)) && str(r.opt(1)) && id is String && HEX.matches(id)) presite.putIfAbsent(k2(r.opt(0) as String, r.opt(1) as String), id) }
        for (r in rows("approved")) { val id = r.opt(2); val at = int(r.opt(3)); if (mine(r.opt(0)) && str(r.opt(1)) && id is String && HEX.matches(id) && at != null) approve(r.opt(0) as String, r.opt(1) as String, id, at) }
    }
    fun clear() { signed.clear(); dels.clear(); removed.clear(); added.clear(); presite.clear(); approved.clear() }
}

/** A verdict (§2): its level, the row that set it (auto-declines count by row, §6), plain words for the card. */
data class Verdict(val level: String, val row: String, val reason: String, val media: Media? = null) {
    data class Media(val files: List<String>, val servers: List<String>?, val expiry: Long, val url: String? = null)
}

object Policy {
    private val RANK = mapOf("silent" to 0, "undo" to 1, "confirm" to 2, "held" to 3, "try-later" to 4, "declined" to 5)
    private fun strictest(vs: List<Verdict>) = vs.fold(Verdict("silent", "ordinary", "")) { a, b -> if (RANK[b.level]!! > RANK[a.level]!!) b else a }
    private val NOT_ITEMS = setOf("d", "title", "description", "image", "alt", "client")
    private val NO_PRIVATE = setOf(3, 10002, 10050, 10019, 10063)
    private val URL = Regex("^(wss?)://([^/?#]*)([^?#]*)(.*)$", RegexOption.IGNORE_CASE)
    private val HASH = Regex("^[0-9a-f]{64}$")
    private const val DAY = 86400L; private const val WEEK = 7 * DAY; private const val AHEAD_S = 300L; private const val BUDGET = 20; private const val MAX_LOOKUPS = 4

    /** A relay URL with a lowercase scheme and host and no trailing slash on its path, as TS's plain string rules. */
    fun normValue(x: String): String = URL.matchEntire(x)?.groupValues?.let { m -> "${m[1].lowercase()}://${m[2].lowercase()}${m[3].trimEnd('/')}${m[4]}" } ?: x
    /** An item's key: [where, name, normalised value], JSON-encoded as TS's JSON.stringify writes it (review 18 L8). */
    fun itemKey(where: String, name: String, value: String) = Jcs.of(JSONArray(listOf(where, name, normValue(value))))
    /** A tag's key in the Undo paths: its name and normalised first value. */
    fun tagKey(t: List<String>) = Jcs.of(JSONArray(listOf(t[0], normValue(t.getOrElse(1) { "" }))))
    private fun tagItems(tags: Any?, where: String): Set<String> {
        val out = LinkedHashSet<String>()
        val list: List<List<Any?>> = when (tags) {
            is List<*> -> tags.mapNotNull { it as? List<Any?> }
            is JSONArray -> (0 until tags.length()).mapNotNull { (tags.opt(it) as? JSONArray)?.let { a -> (0 until a.length()).map { j -> a.opt(j) } } }
            else -> emptyList()
        }
        for (t in list) if (t.size >= 2 && t[0] is String && t[1] is String && t[0] !in NOT_ITEMS) out += itemKey(where, t[0] as String, t[1] as String)
        return out
    }
    /** The plaintext, null when it doesn't decrypt, or the marker NO_KEY when the self key can't be had. */
    const val NO_KEY = "\u0000no-key"
    /** A version's items, public and private; null when its private content can't be read (no self key, or with
     *  `strict` content that doesn't decrypt to a tag array, review 18 M7). */
    fun itemsOf(kind: Int, tags: List<List<String>>, content: String, decrypt: (String) -> String?, strict: Boolean = false): Set<String>? {
        val out = LinkedHashSet(tagItems(tags, "pub"))
        if (kind in NO_PRIVATE || content.isEmpty()) return out
        val plain = decrypt(content)
        if (plain == NO_KEY || (plain == null && strict)) return null
        val t = try { plain?.let { Json.parse(it) } } catch (_: Exception) { null }
        if (strict && t !is JSONArray) return null
        out += tagItems(t, "priv")
        return out
    }
    private fun profileFields(content: String): Map<String, Any?> = try { (Json.parse(content, grammar = true) as? JSONObject)?.let { o -> o.keyList().associateWith { o.opt(it) } } } catch (_: Exception) { null } ?: emptyMap()
    fun filled(content: String): Set<String> = profileFields(content).filter { (_, v) -> v is String && v.any { c -> !Rules.jsSpace(c) } }.keys.map { itemKey("pub", "field", it) }.toSet()

    class Ctx(val g: String, val now: Long, val owner: String, val scopes: List<String>, val history: History, val ledger: Ledger,
              val decrypt: (String) -> String?, val lookup: (List<String>, List<String>) -> List<Event>, val allowed: ((List<String>, String?) -> Boolean)? = null,
              /** Deletions being signed right now, counted as if recorded (review 18 M1). */
              val pending: List<Del> = emptyList())
    private fun dels(c: Ctx) = c.ledger.dels + c.pending
    private fun burstOf(c: Ctx) = dels(c).filter { !it.approved && c.now - it.at < 600 }.sumOf { it.n }

    private fun tag(tags: List<List<String>>, n: String) = tags.firstOrNull { it.size >= 2 && it[0] == n }?.get(1)
    private fun v(level: String, row: String, reason: String, media: Verdict.Media? = null) = Verdict(level, row, reason, media)

    /** Judge an event a site asks to have signed (§2). */
    fun judge(e: Unsigned, c: Ctx): Verdict {
        val out = ArrayList<Verdict>()
        val burst = burstOf(c)
        if (Rules.destructive(e.kind, e.content, e.tags, burst)) out += v("held", "core", coreReason(e))
        val addr = if (Rules.replaceable(e.kind)) Kinds.addrOf(e.kind, e.tags) else null
        if (addr != null && Kinds.judged(e.kind) && e.tags.any { it.isNotEmpty() && it[0] == "expiration" }) out += v("declined", "expiring", "a list that expires")
        if (addr != null && Kinds.judged(e.kind) && e.createdAt - c.now > AHEAD_S) out += v("declined", "ahead", "dated more than 5 minutes ahead")
        if (e.kind == 5) {
            val d = judgeDeletion(e, c, burst, out.any { it.row == "core" })
            if (d.row == "wallet-delete") return if (out.any { it.row == "core" }) v("try-later", "wallet-delete", "too many wallet deletions; try later") else d
            out += d
        } else if (e.kind == 24242 && tag(e.tags, "t") == "delete") out += blossomDelete(e, c)
        else if (e.kind == 27235 && (tag(e.tags, "method") ?: "").uppercase() == "DELETE") {
            val url = tag(e.tags, "u") ?: ""; val h = Regex("([0-9a-f]{64})(?:\\.[A-Za-z0-9]+)?$").find(url)?.groupValues?.get(1)
            val host = Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)").find(url)?.groupValues?.get(1)
            out += if (h != null && c.allowed?.invoke(listOf(h), host) == true) v("silent", "media-delete", "")
            else v("confirm", "media-delete", "Delete $url?", Verdict.Media(listOfNotNull(h), host?.let { listOf(it) }, 0, url))
        } else if (addr != null && Kinds.judged(e.kind)) out += judgeList(e, addr, c)
        return strictest(out)
    }
    private fun coreReason(e: Unsigned) = when {
        e.kind == 5 -> "Delete ${Rules.deletionTargets(e.tags)} events?"
        e.kind == 0 -> "Empty your profile?"
        e.kind == 10002 -> "Leave you with no relays?"
        e.kind == 62 -> "Ask relays to forget everything you posted?"
        e.kind in 1244..1247 -> "Change your key family?"
        else -> "Empty this list?"
    }
    private fun blossomDelete(e: Unsigned, c: Ctx): Verdict {
        val files = e.tags.filter { it.size >= 2 && it[0] == "x" }.map { it[1].lowercase() }
        val exp = tag(e.tags, "expiration")?.let { s -> if (Regex("^(0|[1-9][0-9]{0,15})$").matches(s)) s.toLong() else null }
        val servers = e.tags.filter { it.size >= 2 && it[0] == "server" }.map { it[1] }
        if (files.size > 4 || files.isEmpty() || exp == null || exp - c.now > 600) return v("declined", "media-delete", "a delete token that is too wide")
        if (servers.size <= 1 && c.allowed?.invoke(files, servers.firstOrNull()) == true) return v("silent", "media-delete", "")
        val where = if (servers.isNotEmpty()) servers.joinToString(", ") else "every server they're on"
        return v("confirm", "media-delete", "Delete ${files.size} file${if (files.size > 1) "s" else ""} from $where?", Verdict.Media(files, servers.takeIf { it.isNotEmpty() }, exp))
    }
    private val A_SHAPE = Regex("^(\\d+):([0-9a-fA-F]{64}):")
    /** A deletion's `e` ids and `a` addresses: `?…` for an `a` that names the account but can't be an address. */
    private fun deletionNames(tags: List<List<String>>, g: String): Pair<Set<String>, Set<String>> {
        val ids = LinkedHashSet<String>(); val addrs = LinkedHashSet<String>()
        for (t in tags) if (t.size >= 2) {
            if (t[0] == "e" && HASH.matches(t[1].lowercase())) ids += t[1].lowercase()
            else if (t[0] == "a") { val a = Kinds.addrOfA(t[1], g); if (a != null) addrs += a else { val m = A_SHAPE.find(t[1]); if (m == null || m.groupValues[2].lowercase() == g) addrs += "?${t[1]}" } }
        }
        return ids to addrs
    }
    /** A deletion's distinct targets as the device knows them (an `e` and an `a` naming one event are one). */
    fun distinctTargets(tags: List<List<String>>, h: History, g: String): Int {
        val (ids, addrs) = deletionNames(tags, g); val seen = LinkedHashSet(addrs)
        for (i in ids) { val x = h.get(i); if (x != null && x.pubkey != g) continue; val a = x?.let { if (Rules.replaceable(it.kind)) Kinds.addrOf(it.kind, it.tags) else null }; seen += if (a != null && a in addrs) a else i }
        return seen.size
    }
    private class T(val addr: String?, val ev: Event?, val viaA: Boolean)
    private fun judgeDeletion(e: Unsigned, c: Ctx, burst: Int, held: Boolean): Verdict {
        val (ids, addrs) = deletionNames(e.tags, c.g)
        val missIds = ids.filter { c.history.get(it) == null }; val missAddrs = addrs.filter { !it.startsWith("?") && c.history.current(it) == null }
        val foreign = HashSet<String>()
        if (!held && (missIds.isNotEmpty() || missAddrs.isNotEmpty()) && missIds.size + missAddrs.size <= MAX_LOOKUPS)
            for (x in try { c.lookup(missIds, missAddrs) } catch (_: Exception) { emptyList() }) if (x.id.isNotEmpty() && !c.history.take(x)) foreign += x.id.lowercase()
        val targets = LinkedHashMap<String, T>()
        for (i in ids) {
            val x = c.history.get(i)
            if (i in foreign || (x != null && x.pubkey != c.g)) continue
            val a = x?.let { if (Rules.replaceable(it.kind)) Kinds.addrOf(it.kind, it.tags) else null }
            targets[if (a != null && a in addrs) a else i] = T(a, x, false)
        }
        for (a in addrs) targets[a] = if (a.startsWith("?")) T(null, null, true) else T(a, c.history.current(a), true)
        if (targets.isEmpty()) return v("declined", "delete-none", "nothing of yours to delete")
        val list = targets.values.toList()
        fun kindOf(t: T): Int? = t.ev?.kind ?: t.addr?.substringBefore(':')?.toIntOrNull()
        val ds = dels(c)
        if ("wallet" in c.scopes && list.all { kindOf(it) in setOf(7375, 7376, 7374) }) {
            val n = Rules.deletionTargets(e.tags)
            val mine = ds.count { it.wallet && it.owner == c.owner && c.now - it.at < 600 }
            return if (list.size <= 3 && mine < 3 && burst + n <= 3) v("silent", "wallet-delete", "") else v("try-later", "wallet-delete", "too many wallet deletions; try later")
        }
        val out = ArrayList<Verdict>()
        for (t in list) {
            val k = kindOf(t)
            if (t.ev == null && t.addr == null) { out += v("confirm", "delete-many", "Delete an event this device can't find?"); continue }
            if (k != null && Kinds.judged(k)) {
                val cur = t.addr?.let { c.history.current(it) }
                val newest = t.viaA || cur == null || t.ev == null || t.ev.createdAt >= cur.createdAt
                out += v("confirm", if (newest) "delete-list" else "delete-many", if (newest) (if (k == Kinds.PROFILE) "Delete your profile?" else "Delete this list?") else "Delete an older version of a list?")
            }
        }
        if (list.size >= 2) out += v("confirm", "delete-many", "Delete ${list.size} events?")
        else if (out.isEmpty()) {
            val t = list[0]
            if (t.ev == null) out += v("confirm", "delete-many", "Delete an event this device can't find?")
            else {
                val own = if (t.addr != null) c.history.all(t.addr).all { c.ledger.signed[it.id] == c.owner } else c.ledger.signed[t.ev.id] == c.owner
                val today = ds.count { it.single && it.owner == c.owner && c.now - it.at < DAY }
                out += if (!own) v("confirm", "delete-other", "Delete a post this site didn't make?") else if (today >= BUDGET) v("confirm", "delete-budget", "Delete another post today?") else v("undo", "delete-one", "Deleting a post")
            }
        }
        if (e.createdAt - c.now > AHEAD_S && out.any { it.row == "delete-list" || (it.row == "delete-many" && list.any { t -> kindOf(t)?.let(Kinds::judged) == true }) }) out += v("declined", "ahead", "dated more than 5 minutes ahead")
        return strictest(out)
    }
    /** The newest of the pre-site version, the version from 7 days ago and the last-approved version. */
    fun reference(addr: String, history: History, ledger: Ledger, owner: String, now: Long): Event? {
        val ids = listOfNotNull(ledger.presiteOf(owner, addr), ledger.approvedOf(owner, addr)?.first)
        return (ids.mapNotNull { history.get(it) } + listOfNotNull(history.at(addr, now - WEEK))).fold(null as Event?) { a, b -> if (a == null || b.createdAt > a.createdAt) b else a }
    }
    /** Whether a logged removal still counts: not if a version since has the item again (review 18 L7). */
    private fun stillRemoved(addr: String, item: String, at: Long, c: Ctx, cache: HashMap<String, Set<String>?>): Boolean {
        for (x in c.history.all(addr)) if (x.createdAt > at) {
            val items = cache.getOrPut(x.id) { if (x.kind == Kinds.PROFILE) filled(x.content) else itemsOf(x.kind, x.tags, x.content, c.decrypt) }
            if (items?.contains(item) == true) return false
        }
        return true
    }
    private fun judgeList(e: Unsigned, addr: String, c: Ctx): Verdict {
        val cur = c.history.current(addr); val ref = reference(addr, c.history, c.ledger, c.owner, c.now) ?: cur
        val k = e.kind
        val log = c.ledger.removals(c.owner, addr); val cache = HashMap<String, Set<String>?>()
        val logFull = c.ledger.logCount("removed", c.owner) >= Ledger.LOG_PER_OWNER
        if (k == Kinds.PROFILE) {
            val out = ArrayList<Verdict>()
            val now = filled(e.content); val before = cur?.let { profileFields(it.content) } ?: emptyMap(); val after = profileFields(e.content)
            for (f in listOf("lud16", "lud06", "nip05")) if (cur != null && jsonOf(before[f]) != jsonOf(after[f])) out += v("confirm", "profile", "Change your ${if (f == "nip05") "Nostr address" else "lightning address"}?")
            val removedNow = cur?.let { filled(it.content).filter { f -> f !in now } } ?: emptyList()
            if (logFull && removedNow.isNotEmpty()) out += v("confirm", "profile", "Empty ${removedNow.size} fields of your profile?")
            if (ref != null) {
                val emptied = filled(ref.content).filter { it !in now && (it in removedNow || (it in log && stillRemoved(addr, it, log[it]!!, c, cache))) }
                if (emptied.size >= 2) out += v("confirm", "profile", "Empty ${emptied.size} fields of your profile?")
            }
            return strictest(out)
        }
        if (k in Kinds.WALLET) {
            if (cur == null) return v("silent", "wallet", "")
            if (k == 10019) {
                fun pick(t: List<List<String>>) = t.filter { it.isNotEmpty() && (it[0] == "pubkey" || it[0] == "mint") }.map { Jcs.of(JSONArray(listOf(it[0], normValue(it.getOrElse(1) { "" })))) }.sorted()
                return if (pick(cur.tags) != pick(e.tags)) v("confirm", "wallet-settings", "Change where you receive payments?") else v("silent", "wallet", "")
            }
            // Compared by plaintext: re-saving unchanged settings under a fresh nonce is silent (review 18 L1).
            if (cur.tags != e.tags) return v("confirm", "wallet-settings", "Change your wallet settings?")
            if (cur.content == e.content) return v("silent", "wallet", "")
            val a = c.decrypt(cur.content); val b = c.decrypt(e.content)
            if (a == NO_KEY || b == NO_KEY) return v("confirm", "wallet-settings", "Change your wallet settings?")
            return if ((a ?: cur.content) != (b ?: e.content)) v("confirm", "wallet-settings", "Change your wallet settings?") else v("silent", "wallet", "")
        }
        if (!Kinds.isList(k)) return v("silent", "ordinary", "")
        val after = itemsOf(k, e.tags, e.content, c.decrypt)
        val before = if (cur != null) itemsOf(cur.kind, cur.tags, cur.content, c.decrypt, cur.content != e.content) else emptySet()
        if (after == null || before == null) return v("confirm", "list-removals", "Change a private list this device can't read?")
        val out = ArrayList<Verdict>()
        val removedNow = before.filter { it !in after }
        if (logFull && removedNow.isNotEmpty()) out += v("confirm", "list-removals", "Remove ${removedNow.size} items?")
        if (k in Kinds.RELAY_LISTS) {
            val readOnly = k == 10002 && cur != null && e.tags.any { t -> t.size >= 3 && t[0] == "r" && t[2] == "read" && cur.tags.any { u -> u.size >= 2 && u[0] == "r" && normValue(u[1]) == normValue(t[1]) && u.getOrNull(2) != "read" } }
            if (removedNow.isNotEmpty() || readOnly) out += v("confirm", "relays", if (removedNow.isNotEmpty()) "Remove ${removedNow.size} of your relays?" else "Stop writing to one of your relays?")
            return strictest(out)
        }
        val refItems = if (ref == null || ref === cur) before else itemsOf(ref.kind, ref.tags, ref.content, c.decrypt, ref.content != e.content) ?: return v("confirm", "list-removals", "Change a private list this device can't read?")
        val net = refItems.count { it !in after && (it in before || (it in log && stillRemoved(addr, it, log[it]!!, c, cache))) }
        if ((cur != null && before.isNotEmpty() && after.isEmpty()) || (net > 0 && refItems.all { it !in after })) out += v("confirm", "emptied", "Empty this list?")
        if (net >= 10 || (net >= 5 && net >= 0.2 * refItems.size)) out += v("confirm", "list-removals", "Remove $net of your ${refItems.size} ${if (k == 3) "follows" else "list items"}?")
        return strictest(out)
    }
    private fun jsonOf(x: Any?): String = if (x == null) "null" else try { Jcs.of(x) } catch (_: Exception) { x.toString() }

    /** §3 Undo's date: one second after the newest version and any deletion naming it, or now if later. */
    fun undoDate(h: History, addr: String, now: Long, ids: List<String> = emptyList()): Long {
        val newest = h.current(addr)?.createdAt ?: 0
        val del = (listOf(h.deletedAt[addr] ?: 0L) + ids.map { h.deletedAt[it] ?: 0L }).max()
        return maxOf(now, newest + 1, del + 1)
    }
    const val UNDO_AHEAD_S = 540L
}

/** A card on the signing device (§2 Confirm, §6). */
class Card(val id: Int, val owner: String, val row: String, var reason: String, val events: MutableList<Unsigned>, val at: Long, var media: Verdict.Media?) { @Volatile var shown = false }
/** A deletion waiting its 10 seconds: the notification's Undo cancels it and its twins from the same site. */
class UndoWait(val id: Int, val owner: String, val tags: List<List<String>>, internal val f: CompletableFuture<Boolean>)

/** What the person sees, and what each signed event did (TS `Guard`). */
class Guard(private val d: Device) {
    companion object { private const val HOUR = 3600L; private const val ALLOW_S = 600L; private const val OPEN_PER_SITE = 4
        private val timers = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "keykin-guard").also { it.isDaemon = true } } }
    val cards = ArrayList<Card>()
    private val declines = HashMap<String, MutableList<Pair<Long, String>>>()
    private class Allow(val owner: String, val files: Set<String>, val servers: Set<String>?, val until: Long)
    private val allows = ArrayList<Allow>()
    private val waits = HashMap<Int, MutableList<CompletableFuture<String>>>()
    private val undos = LinkedHashMap<Int, UndoWait>()
    private val approvedIds = HashMap<String, MutableSet<String>>()
    private val pending = ArrayList<Del>()
    private val locks = HashMap<String, java.util.concurrent.locks.ReentrantLock>()
    private var seq = 0
    @Volatile private var recordsAt = 0L
    /** Shown to the app: a new card. */
    @Volatile var onCard: ((Card) -> Unit)? = null
    var undoMs = 10_000L; var cardWaitMs = 120_000L; var quietMs = 1000L
    private val now get() = d.now

    /** Judge with the newest list version and every device's records fetched first; a judged list whose current
     *  version the device can't see is try-later (review 18 M4). */
    fun judge(e: Unsigned, owner: String, scopes: List<String>): Verdict {
        val a = if (Rules.replaceable(e.kind)) Kinds.addrOf(e.kind, e.tags) else null
        if ((a != null && Kinds.judged(e.kind)) || e.kind == 5) if (now - recordsAt >= 30) try { d.refreshRecords(); recordsAt = now } catch (_: Exception) {}
        if (a != null && Kinds.judged(e.kind)) {
            val (answered, asked) = try { d.queryAddr(a).let { (evs, n, of) -> evs.forEach { d.history.take(it) }; n to of } } catch (_: Exception) { 0 to 1 }
            if (d.history.current(a) == null && !(answered >= 1 && answered == asked)) return Verdict("try-later", "unknown-current", "this device can't see your current version yet")
        }
        val pend = synchronized(this) { pending.toList() }
        return Policy.judge(e, Policy.Ctx(d.g, now, owner, scopes, d.history, d.meta.evidence().ledger, d::decryptSelf, d::lookupEvents, { f, s -> allowed(owner, f, s) }, pend))
    }
    /** "sign", "held" (core §5.8's answer is the caller's), or an error for the site. `wait` false (a background
     *  request with no one to ask, as NIP-55's content provider) answers a Confirm or an Undo wait with null. */
    data class Gate(val ok: String?, val error: String?, val verdict: Verdict)
    /** Judge, ask and sign: a site's deletions and list changes one at a time (review 18 M1); a deletion counts from the
     *  moment it is judged until it is recorded. `sign` runs only when it may be signed now. */
    fun <T> serve(e: Unsigned, owner: String, scopes: List<String>, wait: Boolean = true, sign: () -> T): Pair<Gate, T?> {
        val serial = e.kind == 5 || (Rules.replaceable(e.kind) && Kinds.judged(e.kind))
        val lock = if (serial) synchronized(locks) { locks.getOrPut(owner) { java.util.concurrent.locks.ReentrantLock() } } else null
        lock?.lock()
        var reserved: Del? = null
        try {
            val g = gate(e, owner, scopes, wait) {
                if (e.kind == 5) { reserved = Del(now, owner, Rules.deletionTargets(e.tags), Policy.distinctTargets(e.tags, d.history, d.g) == 1, false, false); synchronized(this) { pending += reserved!! } }
            }
            return g to (if (g.ok == "sign") sign() else null)
        } finally { reserved?.let { r -> synchronized(this) { pending.remove(r) } }; lock?.unlock() }
    }
    fun gate(e: Unsigned, owner: String, scopes: List<String>, wait: Boolean = true, judged: () -> Unit = {}): Gate {
        val verdict = judge(e, owner, scopes)
        val auto = Gate(null, "declined: you declined this site's requests a moment ago", verdict)
        val busy = Gate(null, "try-later: too many requests waiting for you", verdict)
        if (verdict.level != "declined" && verdict.level != "try-later") judged()
        return when (verdict.level) {
            "silent" -> Gate("sign", null, verdict)
            "declined" -> Gate(null, "declined: ${verdict.reason}", verdict)
            "try-later" -> Gate(null, "try-later: ${verdict.reason}", verdict)
            "held" -> if (autoDeclined(owner, verdict.row)) auto else Gate("held", null, verdict)
            "undo" -> when {
                autoDeclined(owner, verdict.row) -> auto
                !wait -> Gate(null, null, verdict)
                synchronized(this) { undos.values.count { it.owner == owner } } >= OPEN_PER_SITE -> busy
                undoWait(e, owner) -> Gate("sign", null, verdict)
                else -> Gate(null, "declined: undone", verdict)
            }
            else -> when {
                autoDeclined(owner, verdict.row) -> auto
                !wait -> Gate(null, null, verdict)
                synchronized(this) { val joins = verdict.row == "media-delete" && cards.any { it.owner == owner && it.row == "media-delete" && !it.shown && it.media?.url == null }
                    !joins && cards.count { it.owner == owner } >= OPEN_PER_SITE } -> busy
                else -> when (ask(e, owner, verdict)) { "allow" -> Gate("sign", null, verdict); "decline" -> Gate(null, "declined: you declined it", verdict); else -> Gate(null, "try-later: waiting for you on your phone", verdict) }
            }
        }
    }
    private fun ask(e: Unsigned, owner: String, verdict: Verdict): String {
        val f = CompletableFuture<String>()
        val card: Card
        synchronized(this) {
            val join = if (verdict.row == "media-delete" && verdict.media != null && verdict.media.url == null) cards.firstOrNull { it.owner == owner && it.row == "media-delete" && !it.shown && it.media?.url == null } else null
            if (join != null && verdict.media != null) {
                val m = join.media!!; join.events += e
                val files = (m.files + verdict.media.files).distinct()
                val servers = if (m.servers == null || verdict.media.servers == null) null else (m.servers + verdict.media.servers).distinct()
                join.media = Verdict.Media(files, servers, maxOf(m.expiry, verdict.media.expiry))
                join.reason = "Delete ${files.size} file${if (files.size > 1) "s" else ""} from ${servers?.joinToString(", ") ?: "every server they're on"}?"
                card = join
            } else {
                card = Card(++seq, owner, verdict.row, verdict.reason, mutableListOf(e), now, verdict.media)
                cards += card
                timers.schedule({ if (synchronized(this) { card in cards }) { card.shown = true; onCard?.invoke(card) } }, if (verdict.row == "media-delete") quietMs else 0, TimeUnit.MILLISECONDS)
            }
            waits.getOrPut(card.id) { ArrayList() } += f
        }
        return try { f.get(cardWaitMs, TimeUnit.MILLISECONDS) } catch (_: Exception) { answer(card.id, "gone"); "gone" }
    }
    /** The person allowed these on a screen of the app's own (NIP-55's request screen, a card). */
    fun allowNow(owner: String, vararg events: Unsigned) { synchronized(this) { approvedIds.getOrPut(owner) { HashSet() } += events.map { it.id } } }
    /** The person's answer to a card: an Allow of media deletes covers only its files and servers for 10 minutes;
     *  an allowed list change is that site's last-approved version. */
    fun answer(id: Int, a: String) {
        val fs: List<CompletableFuture<String>>
        synchronized(this) {
            val c = cards.firstOrNull { it.id == id } ?: return
            cards.remove(c)
            if (a == "decline") declined(c.owner, c.row)
            if (a == "allow") { c.media?.let { m -> allows += Allow(c.owner, m.files.toSet(), m.servers?.toSet(), now + ALLOW_S) }; allowNow(c.owner, *c.events.toTypedArray()) }
            fs = waits.remove(id) ?: emptyList()
        }
        for (f in fs) f.complete(a)
    }
    @Synchronized private fun allowed(owner: String, files: List<String>, server: String?): Boolean {
        allows.removeAll { it.until <= now }
        return allows.any { it.owner == owner && files.all { f -> f in it.files } && (it.servers == null || (server != null && server in it.servers)) }
    }
    /** A decline by the person (a card's Decline, or an Undo of the site's change). */
    @Synchronized fun declined(owner: String, row: String) { val q = declines.getOrPut(owner) { ArrayList() }; q.removeAll { now - it.first >= HOUR }; q += now to row }
    @Synchronized private fun autoDeclined(owner: String, row: String): Boolean {
        val q = (declines[owner] ?: emptyList<Pair<Long, String>>()).filter { now - it.first < HOUR }
        return q.size >= 6 || q.count { it.second == row } >= 3
    }
    /** Each wait has its own id and remembers its site (review 18 M2, L3). */
    private fun undoWait(e: Unsigned, owner: String): Boolean {
        val w = synchronized(this) { UndoWait(++seq, owner, e.tags, CompletableFuture()).also { undos[it.id] = it } }
        return try { w.f.get(undoMs, TimeUnit.MILLISECONDS) } catch (_: java.util.concurrent.TimeoutException) { true } catch (_: Exception) { false } finally { synchronized(this) { undos.remove(w.id) } }
    }
    @Synchronized fun pendingUndos(): List<UndoWait> = undos.values.toList()
    /** Undo a waiting deletion and every twin from the same site naming the same targets: one decline (§6). */
    fun undoPending(id: Int): Boolean {
        val twins = synchronized(this) { val u = undos[id] ?: return false; undos.values.filter { it.owner == u.owner && it.tags == u.tags } }
        twins.forEach { it.f.complete(false) }; declined(twins[0].owner, "delete-one"); return true
    }

    /** After an event was signed for `owner`: the history takes it, and the records say what it did. Never throws a
     *  bookkeeping fault over a signed event (review 18 M5). */
    fun signed(e: Event, owner: String, approved: Boolean = false) {
        val all = d.meta.evidence().ledger
        val a = if (Rules.replaceable(e.kind)) Kinds.addrOf(e.kind, e.tags) else null
        val prev = a?.let { d.history.current(it) }
        val approvedNow = approved || synchronized(this) { approvedIds[owner]?.remove(e.id) == true }
        val judgedList = a != null && Kinds.judged(e.kind) && owner != "member"
        var removed = emptyList<String>(); var added = emptyList<String>(); var n = 0; var single = false; var wallet = false
        try {
            if (judgedList) {
                val before = if (prev == null) emptySet() else if (e.kind == Kinds.PROFILE) Policy.filled(prev.content) else Policy.itemsOf(prev.kind, prev.tags, prev.content, d::decryptSelf)
                val after = if (e.kind == Kinds.PROFILE) Policy.filled(e.content) else Policy.itemsOf(e.kind, e.tags, e.content, d::decryptSelf)
                if (before != null && after != null) { removed = before.filter { it !in after }; added = after.filter { it !in before } }
            }
            if (e.kind == 5) {
                n = Rules.deletionTargets(e.tags)
                val es = e.tags.filter { it.size >= 2 && it[0] == "e" }
                wallet = n > 0 && e.tags.none { it.isNotEmpty() && it[0] == "a" } && es.isNotEmpty() && es.all { d.history.get(it[1])?.kind in setOf(7375, 7376, 7374) }
                // The daily budget counts distinct targets, never wallet deletions (review 18 L2).
                single = !wallet && Policy.distinctTargets(e.tags, d.history, d.g) == 1
            }
        } catch (_: Exception) {}
        // Never a pre-site version this grant signed itself (review 18 M4).
        val firstChange = judgedList && prev != null && all.presiteOf(owner, a!!) == null && all.signed[prev.id] != owner
        if (firstChange) d.history.pin(prev!!)
        d.meta.record { led ->
            led.sign(e.id, owner)
            if (e.kind == 5) led.del(Del(now, owner, n, single, wallet, approved))
            if (judgedList) {
                if (firstChange) led.setPresite(owner, a!!, prev!!.id)
                if (approvedNow) led.approve(owner, a!!, e.id, now)
                led.log("removed", owner, a!!, removed, now); led.log("added", owner, a, added, now)
            }
        }
        d.history.take(e, true)
    }
    @Synchronized fun dump(): JSONObject = JSONObject()
        .put("declines", JSONArray(declines.map { (o, q) -> JSONArray(listOf(o, JSONArray(q.map { JSONObject().put("at", it.first).put("row", it.second) }))) }))
        .put("allows", JSONArray(allows.map { JSONObject().put("owner", it.owner).put("files", JSONArray(it.files.toList())).put("servers", it.servers?.let { s -> JSONArray(s.toList()) } ?: "*").put("until", it.until) }))
    @Synchronized fun load(x: JSONObject?) {
        declines.clear(); allows.clear(); if (x == null) return
        x.optJSONArray("declines")?.let { a -> for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> declines[p.getString(0)] = p.getJSONArray(1).let { q -> (0 until q.length()).map { j -> q.getJSONObject(j).let { o -> o.getLong("at") to o.getString("row") } }.toMutableList() } } }
        x.optJSONArray("allows")?.let { a -> for (i in 0 until a.length()) a.optJSONObject(i)?.let { o ->
            fun strs(v: Any?) = (v as? JSONArray)?.let { s -> (0 until s.length()).map { s.getString(it) }.toSet() }
            allows += Allow(o.getString("owner"), strs(o.opt("files")) ?: emptySet(), strs(o.opt("servers")), o.getLong("until")) } }
    }
    fun clear() { val fs = synchronized(this) { cards.clear(); declines.clear(); allows.clear(); pending.clear(); val w = waits.values.flatten(); waits.clear(); w }; fs.forEach { it.complete("gone") }; synchronized(this) { undos.values.toList() }.forEach { it.f.complete(false) } }
}
