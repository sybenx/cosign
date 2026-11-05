// Device policy §1's metadata, synced, as the TS reference's device/metadata.ts: each device's encrypt records
// and the kinds of the account's events by ciphertext hash (Doors §1's evidence), one cumulative snapshot per
// device per month in signed, numbered parts (part 0 listing every part's number and hash) and an index of live
// months, all account-signed kind 30078 under unlinkable keykin-meta d's, encrypted under the data key bound to
// g, d and the state. A reader takes the index first, never a lower number, only parts the index names, and only
// a current device's; decrypts to self are judged on every current device's records. Each month also carries
// Device policy §1's records (Policy.kt's Ledger).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

class MetaStore(private val d: Device) {
    companion object {
        const val KIND = 30078
        private const val PART_PLAIN = 16_000
        private const val MAX_PARTS = 64
        private const val KEEP_MONTHS = 13
        /** YYYY-MM in UTC, ASCII digits whatever the device's locale (review 17 M5). */
        fun monthOf(unix: Long): String = java.time.Instant.ofEpochSecond(unix).atZone(java.time.ZoneOffset.UTC).let { String.format(java.util.Locale.ROOT, "%04d-%02d", it.year, it.monthValue) }
        /** The last `n` calendar months up to `unix`'s (review 17 M4). */
        fun lastMonths(unix: Long, n: Int): List<String> { val z = java.time.Instant.ofEpochSecond(unix).atZone(java.time.ZoneOffset.UTC).toLocalDate().withDayOfMonth(1)
            return (0 until n).map { k -> z.minusMonths(k.toLong()).let { String.format(java.util.Locale.ROOT, "%04d-%02d", it.year, it.monthValue) } } }
        private fun u16(n: Int) = byteArrayOf(((n shr 8) and 0xff).toByte(), (n and 0xff).toByte())
        private fun key(baseDk: String) = hkdf32(unhex(baseDk), utf8("keykin-meta-d/1"))
        fun partD(baseDk: String, member: String, month: String, part: Int) = "keykin-meta:" + hex(hmac(key(baseDk), unhex(member) + utf8(month) + u16(part)))
        fun indexD(baseDk: String, member: String) = "keykin-meta-index:" + hex(hmac(key(baseDk), unhex(member)))
        private fun contentKey(dk: ByteArray) = hkdf32(dk, utf8("keykin-meta/1"))
        private fun aad(g: String, d: String, state: String) = unhex(g) + utf8(d) + unhex(state)
        fun partDigest(g: String, d: String, body: JSONObject) = sha(utf8("keykin-meta/1"), unhex(g), utf8(d), utf8(Jcs.of(body)))
        fun indexDigest(g: String, d: String, body: JSONObject) = sha(utf8("keykin-meta-index/1"), unhex(g), utf8(d), utf8(Jcs.of(body)))
        private val HASH = Regex("^[0-9a-f]{64}$")
        private fun toData(e: Evidence): JSONObject = e.ledger.data()
            .put("encrypt", JSONArray(e.owners.flatMap { (h, os) -> os.map { o -> JSONArray(listOf(h, o)) } }))
            .put("events", JSONArray(e.kinds.flatMap { (h, ks) -> ks.map { x -> JSONArray(listOf(h, x.substringBefore(':').toInt(), x.substringAfter(':'))) } }))
        /** A maker's records: only its member app or its own grants as owners and signers (L5); a malformed entry
         *  costs only itself, and kinds are whole numbers 0–65535 as TS reads them (L4). */
        private fun fromData(x: JSONObject, into: Evidence = Evidence(), maker: String? = null): Evidence {
            fun mine(o: Any?) = o is String && (o == "member" || maker == null || o.startsWith("$maker:"))
            fun int(v: Any?) = (v as? Number)?.takeIf { it is Int || it is Long || (it is Double && it % 1.0 == 0.0) }?.toLong()
            x.optJSONArray("encrypt")?.let { a -> for (i in 0 until a.length()) (a.opt(i) as? JSONArray)?.let { p -> val h = p.opt(0) as? String; val o = p.opt(1)
                if (h != null && HASH.matches(h) && mine(o)) into.owners.getOrPut(h) { LinkedHashSet() } += o as String } }
            x.optJSONArray("events")?.let { a -> for (i in 0 until a.length()) (a.opt(i) as? JSONArray)?.let { p -> val h = p.opt(0) as? String; val k = int(p.opt(1)); val sg = p.opt(2)
                if (h != null && HASH.matches(h) && k != null && k in 0..65535 && mine(sg)) into.kinds.getOrPut(h) { LinkedHashSet() } += "$k:$sg" } }
            into.ledger.take(x, ::mine)
            return into
        }
    }
    /** A whole number as the strict parser gives it (Long) or as it was put (Int); null for anything else. */
    private fun whole(v: Any?): Int? = when (v) { is Int -> v; is Long -> if (v in 0..Int.MAX_VALUE) v.toInt() else null; else -> null }
    private val own = LinkedHashMap<String, Evidence>()
    private val sent = LinkedHashMap<String, List<Pair<Int, String>>>()
    private var indexSeq = 0
    var lastAt = 0L; private set
    val dirty = LinkedHashSet<String>()
    private val others = HashMap<String, Map<String, Evidence>>()
    private val seenIndex = HashMap<String, Int>()
    private val seenPart = HashMap<String, Int>()
    @Volatile private var merged: Evidence? = null
    private var mergedFor = ""
    private val gen = HashMap<String, Int>()
    private val now get() = System.currentTimeMillis() / 1000
    private fun current() = d.view.devices.filter { it !in d.view.removed }.toSet()

    @Synchronized private fun bucket(): Evidence { val m = monthOf(now); dirty += m; gen[m] = (gen[m] ?: 0) + 1; merged = null; return own.getOrPut(m) { Evidence() } }
    @Synchronized fun encrypted(payload: String, owner: String) = bucket().encrypted(payload, owner)
    @Synchronized fun event(kind: Int, content: String, signer: String = "member") { if (Evidence.hashOf(content) != null) bucket().event(kind, content, signer) }
    /** Add to this month's policy records (Device policy §1); the merged view is rebuilt after. */
    @Synchronized fun record(f: (Ledger) -> Unit) { f(bucket().ledger); merged = null }
    /** Every current device's records together: what a decrypt is judged on. */
    @Synchronized fun evidence(): Evidence {
        val cur = current(); val key = cur.sorted().joinToString(",")
        merged?.let { if (mergedFor == key) return it }
        val all = Evidence()
        for (e in own.values) fromData(toData(e), all)
        for ((m, months) in others) if (m in cur) for (e in months.values) fromData(toData(e), all, m)
        mergedFor = key
        return all.also { merged = it }
    }

    /** Publish what changed: the changed months' parts (part 0 with every change) and the index. */
    fun publish(net: RelayNet): List<JSONObject> {
        val b = build(d.g) ?: return emptyList()
        val signed = b.events.map { u -> d.sign(u.kind, u.content, u.tags, u.createdAt) }
        for (e in signed) net.publishEvent(e)
        // Only now, every event handed to the relays, is it what this device sent (review 17 M3).
        synchronized(this) { sent.clear(); sent.putAll(b.sent); indexSeq = b.indexSeq; for ((m, g0) in b.seen) if ((gen[m] ?: 0) == g0) dirty.remove(m) }
        return signed
    }
    /** For tests: what `publish` would send, unsigned, built for account `g`. */
    internal fun unsignedForTest(g: String): List<Unsigned> = build(g)?.events ?: emptyList()
    private class Built(val events: List<Unsigned>, val sent: Map<String, List<Pair<Int, String>>>, val indexSeq: Int, val seen: Map<String, Int>)
    @Synchronized private fun build(g: String): Built? {
        val (state, dk) = d.dataKey()
        val out = ArrayList<Unsigned>()
        val keep = lastMonths(now, KEEP_MONTHS).toSet()
        own.keys.filter { it !in keep }.forEach { own.remove(it); sent.remove(it) }
        if (dirty.isEmpty()) return null
        // The date is reserved here, so two publishes never share one (review 17 L7).
        val at = maxOf(now, lastAt + 1); lastAt = at
        val newSent = LinkedHashMap(sent); val seen = dirty.associateWith { gen[it] ?: 0 }
        val rnd = SecureRandom()
        fun seal(dd: String, body: JSONObject, digest: ByteArray) {
            val text = Jcs.of(JSONObject(body.toString()).put("sig", Keykin.secp.schnorrSign(digest, d.sk, ByteArray(32).also(rnd::nextBytes))))
            val box = XChaCha.seal(contentKey(dk), ByteArray(24).also(rnd::nextBytes), utf8(text), aad(g, dd, state))
            out += Unsigned(g, at, KIND, listOf(listOf("d", dd), listOf("state", state)), Base64.getEncoder().encodeToString(box))
        }
        for (month in dirty.filter { own.containsKey(it) }) {
            // A month that won't fit sheds its oldest records, never the whole sync (review 17 H2).
            var text = Jcs.of(toData(own[month]!!))
            // Removal logs and recent deletions go only when nothing else is left to shed (review 18 H1).
            while ((text.length + PART_PLAIN - 1) / PART_PLAIN > MAX_PARTS) {
                val e = own[month]!!; val size = e.size(); val n = maxOf(1, (size + 9) / 10)
                e.trim(n, now); if (e.size() == size) e.ledger.trimLogs(n)
                text = Jcs.of(toData(e)); merged = null
            }
            val chunks = if (text.isEmpty()) listOf("") else text.chunked(PART_PLAIN)
            val prev = newSent[month] ?: emptyList()
            val parts = chunks.mapIndexed { k, c ->
                val h = hex(sha(utf8(c))); val same = k > 0 && prev.getOrNull(k)?.second == h
                Triple(if (same) prev[k].first else (prev.getOrNull(k)?.first ?: 0) + 1, h, c) to !same
            }
            for ((k, pc) in parts.withIndex()) if (pc.second) {
                val (seq, _, data) = pc.first
                val dd = partD(d.baseDataKey(), d.pub, month, k)
                val body = JSONObject().put("seq", seq).put("month", month).put("part", k).put("data", data)
                if (k == 0) body.put("parts", JSONArray(parts.map { JSONArray(listOf(it.first.first, it.first.second)) }))
                seal(dd, body, partDigest(g, dd, body))
            }
            newSent[month] = parts.map { it.first.first to it.first.second }
        }
        val ix = indexSeq + 1
        val dd = indexD(d.baseDataKey(), d.pub)
        val body = JSONObject().put("seq", ix).put("months", JSONObject().also { o -> newSent.forEach { (m, ps) -> o.put(m, JSONArray(ps.map { it.first })) } })
        seal(dd, body, indexDigest(g, dd, body))
        return Built(out, newSent, ix, seen)
    }

    /** Read every other current device's snapshots from `events`: its index first, then what it names. */
    @Synchronized fun take(events: List<Event>) {
        fun open(e: Event): JSONObject? = try {
            val dd = e.tag("d") ?: ""; val state = e.tag("state") ?: ""
            val k = d.dataKeyFor(state) ?: return null
            Json.obj(Json.utf8Strict(XChaCha.open(contentKey(k), Base64.getDecoder().decode(e.content), aad(d.g, dd, state))))
        } catch (_: Exception) { null }
        val byD = events.filter { it.kind == KIND && it.pubkey == d.g && verifyEvent(it) }.groupBy { it.tag("d") ?: "" }
        fun newest(dd: String, ok: (JSONObject) -> Boolean): JSONObject? {
            for (e in (byD[dd] ?: emptyList()).sortedByDescending { it.createdAt }) { val x = open(e) ?: continue; if (ok(x)) return x }
            return null
        }
        fun body(x: JSONObject) = JSONObject(x.toString()).also { it.remove("sig") }
        for (m in current()) {
            val id = indexD(d.baseDataKey(), m)
            val ix = newest(id) { x -> whole(x.opt("seq")) != null && schnorrVerify(x.optString("sig"), indexDigest(d.g, id, body(x)), m) } ?: continue
            // A restored copy of this device continues its own numbers above what it published before (L2).
            if (m == d.pub) {
                if (whole(ix.opt("seq"))!! > indexSeq) { indexSeq = whole(ix.opt("seq"))!!
                    ix.optJSONObject("months")?.let { mo -> for (month in mo.keyList()) if (!sent.containsKey(month)) mo.optJSONArray(month)?.let { a -> sent[month] = (0 until a.length()).map { (whole(a.opt(it)) ?: 0) to "" }; dirty += month } } }
                continue
            }
            val iseq = ix.getInt("seq"); if (iseq < (seenIndex[m] ?: 0)) continue
            seenIndex[m] = iseq
            val months = LinkedHashMap<String, Evidence>()
            val mo = ix.optJSONObject("months") ?: JSONObject()
            for (month in mo.keyList()) {
                val seqs = mo.optJSONArray(month)?.let { a -> (0 until a.length()).map { (a.opt(it) as? Number)?.toInt() ?: -1 } } ?: continue
                if (!Regex("^\\d{4}-\\d{2}$").matches(month) || seqs.isEmpty() || seqs.size > MAX_PARTS) continue
                val parts = ArrayList<JSONObject>()
                for (k in seqs.indices) {
                    val dd = partD(d.baseDataKey(), m, month, k)
                    val x = newest(dd) { p -> whole(p.opt("part")) == k && p.opt("month") == month && whole(p.opt("seq"))?.let { s -> s >= seqs[k] && s >= (seenPart["$m:$month:$k"] ?: 0) } == true &&
                        schnorrVerify(p.optString("sig"), partDigest(d.g, dd, body(p)), m) } ?: break
                    parts += x
                }
                // Anything short of a whole, consistent month keeps what was read before (review 17 M2).
                val keepPrev = { others[m]?.get(month)?.let { months[month] = it } }
                if (parts.size != seqs.size) { keepPrev(); continue }
                val list = parts[0].optJSONArray("parts") ?: run { keepPrev(); null } ?: continue
                if (list.length() != parts.size || parts.withIndex().any { (k, p) -> (list.opt(k) as? JSONArray)?.let { l -> whole(l.opt(0)) != whole(p.opt("seq")) || l.opt(1) != hex(sha(utf8(p.optString("data")))) } ?: true }) { keepPrev(); continue }
                try { months[month] = fromData(Json.obj(parts.joinToString("") { it.getString("data") }), Evidence(), m) } catch (_: Exception) { keepPrev(); continue }
                parts.withIndex().forEach { (k, p) -> seenPart["$m:$month:$k"] = p.getInt("seq") }
            }
            others[m] = months
        }
        merged = null
    }

    /** The part d's the indexes among `events` name (a second, narrow fetch). */
    @Synchronized fun namedParts(events: List<Event>): List<String> {
        val out = ArrayList<String>()
        for (m in current()) for (e in events) if (e.tag("d") == indexD(d.baseDataKey(), m)) try {
            val k = d.dataKeyFor(e.tag("state") ?: "") ?: continue
            val x = Json.obj(Json.utf8Strict(XChaCha.open(contentKey(k), Base64.getDecoder().decode(e.content), aad(d.g, e.tag("d")!!, e.tag("state")!!))))
            x.optJSONObject("months")?.let { mo -> for (month in mo.keyList()) for (p in 0 until minOf(mo.optJSONArray(month)?.length() ?: 0, MAX_PARTS)) out += partD(d.baseDataKey(), m, month, p) }
        } catch (_: Exception) {}
        return out.distinct()
    }
    @Synchronized fun dump(): JSONObject = JSONObject()
        .put("own", JSONArray(own.map { (m, e) -> JSONArray(listOf(m, e.dump())) }))
        .put("sent", JSONArray(sent.map { (m, ps) -> JSONArray(listOf(m, JSONArray(ps.map { JSONObject().put("seq", it.first).put("hash", it.second) }))) }))
        .put("indexSeq", indexSeq).put("lastAt", lastAt).put("dirty", JSONArray(dirty.toList()))
        .put("others", JSONArray(others.map { (m, ms) -> JSONArray(listOf(m, JSONArray(ms.map { (mo, e) -> JSONArray(listOf(mo, e.dump())) }))) }))
        .put("seenIndex", JSONArray(seenIndex.map { (k, v) -> JSONArray(listOf(k, v)) })).put("seenPart", JSONArray(seenPart.map { (k, v) -> JSONArray(listOf(k, v)) }))
    @Synchronized fun load(x: JSONObject?) {
        if (x == null) return
        fun ev(o: JSONObject) = Evidence().also { it.load(o) }
        own.clear(); x.optJSONArray("own")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> own[p.getString(0)] = ev(p.getJSONObject(1)) } }
        sent.clear(); x.optJSONArray("sent")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> sent[p.getString(0)] = p.getJSONArray(1).let { l -> (0 until l.length()).map { l.getJSONObject(it).let { q -> q.getInt("seq") to q.getString("hash") } } } } }
        indexSeq = x.optInt("indexSeq"); lastAt = x.optLong("lastAt")
        dirty.clear(); x.optJSONArray("dirty")?.let { a -> for (i in 0 until a.length()) dirty += a.getString(i) }
        others.clear(); x.optJSONArray("others")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> others[p.getString(0)] = p.getJSONArray(1).let { l -> (0 until l.length()).associate { l.getJSONArray(it).let { q -> q.getString(0) to ev(q.getJSONObject(1)) } } } } }
        seenIndex.clear(); x.optJSONArray("seenIndex")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> seenIndex[p.getString(0)] = p.getInt(1) } }
        seenPart.clear(); x.optJSONArray("seenPart")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> seenPart[p.getString(0)] = p.getInt(1) } }
        merged = null
    }
    @Synchronized fun clear() { own.clear(); sent.clear(); others.clear(); dirty.clear(); seenIndex.clear(); seenPart.clear(); merged = null }
}
