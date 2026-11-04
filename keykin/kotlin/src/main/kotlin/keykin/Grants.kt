// Grants (Doors §1–§2), as the TS reference's device/grants.ts: entries signed by the device that made them;
// one kind 30078 event per device, account-signed, under a `d` relays can't link to a member key, encrypted
// under the current data key with g, d and the state hash as associated data, split into parts past 24 KB;
// every device reads every current maker's newest event, for listing and signing out. A grant ended once never
// comes back; a removed device's grants are gone. A grant applies only on its own connection.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

object Grants {
    const val KIND = 30078
    val SCOPES = listOf("sign-in", "post", "lists", "dms", "private-data", "wallet")
    private const val PART_PLAIN = 17_000
    private val rnd = SecureRandom()

    private fun body(e: JSONObject) = JSONObject(e.toString()).also { it.remove("by_sig") }
    fun entryDigest(g: String, e: JSONObject): ByteArray = sha(utf8("keykin-grant/1"), unhex(g), utf8(Jcs.of(body(e))))
    fun signEntry(g: String, sk: ByteArray, e: JSONObject): JSONObject {
        val full = JSONObject(e.toString()).put("by", Keykin.secp.pub(sk)).also { it.remove("by_sig") }
        return full.put("by_sig", Keykin.secp.schnorrSign(entryDigest(g, full), sk, ByteArray(32).also(rnd::nextBytes)))
    }
    fun entryOk(g: String, e: JSONObject): Boolean = try { schnorrVerify(e.getString("by_sig"), entryDigest(g, e), e.getString("by")) } catch (_: Exception) { false }
    fun expired(e: JSONObject, now: Long, lastUsed: Long?): Boolean = when (val x = e.opt("expiry")) {
        "unused-90d" -> now - (lastUsed ?: e.optLong("made")) > 90 * 86400
        is Number -> now > x.toLong()
        else -> false
    }

    /** §2: `d = "keykin-grants:" ‖ hex(first 16 bytes of HMAC-SHA256(HKDF(base data key, "keykin-grants-d/1"), member key))`. */
    fun d(baseDk: String, member: String) = "keykin-grants:" + hex(hmac(hkdf32(unhex(baseDk), utf8("keykin-grants-d/1")), unhex(member)).copyOf(16))
    private fun contentKey(dk: ByteArray) = hkdf32(dk, utf8("keykin-grants/1"))
    private fun aad(g: String, d: String, state: String) = unhex(g) + utf8(d) + unhex(state)
    private fun setJson(set: JSONObject) = JSONObject().put("entries", set.getJSONArray("entries")).put("tombstones", set.getJSONArray("tombstones")).put("ended", set.getJSONArray("ended")).put("union", set.getJSONArray("union"))
    fun setDigest(g: String, d: String, createdAt: Long, set: JSONObject): ByteArray = sha(utf8("keykin-grant-set/1"), unhex(g), utf8(d), u64(createdAt), sha(utf8(Jcs.of(setJson(set)))))

    /** The maker's event(s) for `set` ({entries, tombstones, ended, union}), unsigned: one, or parts `d:1`, `d:2`, … */
    fun events(g: String, makerSk: ByteArray, baseDk: String, state: String, dk: ByteArray, set: JSONObject, createdAt: Long): List<Unsigned> {
        val d = d(baseDk, Keykin.secp.pub(makerSk))
        val text = Jcs.of(setJson(set).put("maker_sig", Keykin.secp.schnorrSign(setDigest(g, d, createdAt, set), makerSk, ByteArray(32).also(rnd::nextBytes))))
        val chunks = text.chunked(PART_PLAIN)
        return chunks.mapIndexed { k, c ->
            val dd = if (chunks.size == 1) d else "$d:${k + 1}"
            val box = XChaCha.seal(contentKey(dk), ByteArray(24).also(rnd::nextBytes), utf8(c), aad(g, dd, state))
            val tags = listOf(listOf("d", dd), listOf("state", state)) + if (chunks.size > 1) listOf(listOf("parts", chunks.size.toString())) else emptyList()
            Unsigned(g, createdAt, KIND, tags, Base64.getEncoder().encodeToString(box))
        }
    }
    data class Read(val at: Long, val set: JSONObject)
    /** A maker's newest complete, verified set among `events`, or null. */
    fun read(g: String, maker: String, baseDk: String, keyFor: (String) -> ByteArray?, events: List<Event>): Read? {
        val d = d(baseDk, maker)
        val mine = events.filter { e -> e.kind == KIND && e.pubkey == g && e.tag("d").let { it == d || it?.startsWith("$d:") == true } && verifyEvent(e) }
        for (at in mine.map { it.createdAt }.distinct().sortedDescending()) try {
            val same = mine.filter { it.createdAt == at }
            val n = same[0].tag("parts")?.toInt() ?: 1
            val parts = if (n == 1) listOf(same.firstOrNull { it.tag("d") == d }) else (1..n).map { k -> same.firstOrNull { it.tag("d") == "$d:$k" } }
            if (parts.any { it == null }) continue
            val text = parts.joinToString("") { p ->
                val state = p!!.tag("state") ?: ""
                val key = keyFor(state) ?: refuse("no_key")
                Json.utf8Strict(XChaCha.open(contentKey(key), Base64.getDecoder().decode(p.content), aad(g, p.tag("d")!!, state)))
            }
            val x = Json.obj(text)
            val set = JSONObject().put("entries", x.optJSONArray("entries") ?: JSONArray()).put("tombstones", x.optJSONArray("tombstones") ?: JSONArray())
                .put("ended", x.optJSONArray("ended") ?: JSONArray()).put("union", x.optJSONArray("union") ?: JSONArray())
            if (!schnorrVerify(x.optString("maker_sig"), setDigest(g, d, at, set), maker)) continue
            return Read(at, set)
        } catch (_: Exception) { /* a part we can't open, or a forgery: the next older one */ }
        return null
    }

    // --- which scope a request needs (§1) --------------------------------------------------------
    private val WALLET = setOf(17375, 37375, 7375, 7376, 7374, 10019)
    private val SIGN_IN = setOf(22242, 27235, 24242)
    private fun isList(k: Int) = k == 0 || k == 3 || k == 10002 || k == 10050 || k in 10000 until 10102 || k in 30000..30030
    fun scopeForEvent(kind: Int) = when { kind in SIGN_IN -> "sign-in"; kind in WALLET -> "wallet"; isList(kind) -> "lists"; else -> "post" }
    private val LIST_TAGS = setOf("p", "e", "a", "t", "r", "word", "emoji", "group", "relay")
    private val WALLET_FIELDS = setOf("privkey", "mint", "proofs", "direction", "amount", "unit", "balance")
    /** As TS `scopeForDecrypt`: `dms` with someone else's key; a decrypt-to-self judged from its plaintext. */
    fun scopeForDecrypt(g: String, peer: String, plaintext: String?): String {
        if (peer.lowercase() != g) return "dms"
        if (plaintext == null) return "private-data"
        try {
            val v = org.json.JSONTokener(plaintext).nextValue()
            if (v is JSONObject && v.optString("pubkey") == g && v.optInt("kind", -1) in setOf(14, 15, 7, 5)) return "dms"
            if (v is JSONArray && (0 until v.length()).all { (v.opt(it) as? JSONArray)?.opt(0) is String }) {
                val names = (0 until v.length()).map { v.getJSONArray(it).getString(0) }
                if (names.any { it in WALLET_FIELDS }) return "wallet"
                if (names.all { it in LIST_TAGS }) return "lists"
            }
        } catch (_: Exception) {}
        return "private-data"
    }
}

/** One device's grants (Doors §1–§2), as TS `GrantStore`. */
class GrantStore(private val d: Device) {
    val own = LinkedHashMap<String, JSONObject>()
    private val tombstones = ArrayList<JSONObject>()
    private val ended = ArrayList<JSONObject>()
    private val union = LinkedHashMap<String, JSONObject>()
    private val others = HashMap<String, Grants.Read>()
    private val lastUsed = HashMap<String, Long>()
    private var lastPublish = 0L
    private val now get() = System.currentTimeMillis() / 1000
    private fun current() = d.view.devices.filter { it !in d.view.removed }.toSet()

    /** A new grant, from a human act on this device only. */
    @Synchronized fun make(site: String, says: String, door: String, connection: String, scopes: List<String>, relays: List<String>? = null, signer: String? = null): JSONObject {
        val e = JSONObject().put("id", hex(ByteArray(16).also { SecureRandom().nextBytes(it) })).put("v", 1).put("site", site).put("says", says).put("door", door).put("connection", connection)
            .put("scopes", JSONArray(scopes.distinct().sorted())).put("borrowed", false).put("helper", false).put("made", now).put("expiry", "unused-90d")
        relays?.let { e.put("relays", JSONArray(it)) }; signer?.let { e.put("signer", it) }
        val s = Grants.signEntry(d.g, d.sk, e); own[s.getString("id")] = s; return s
    }
    @Synchronized fun widen(id: String, scopes: List<String>): JSONObject {
        val e = own[id] ?: refuse("unknown_grant")
        val cur = (0 until e.getJSONArray("scopes").length()).map { e.getJSONArray("scopes").getString(it) }
        val w = Grants.signEntry(d.g, d.sk, JSONObject(e.toString()).put("v", e.getInt("v") + 1).put("scopes", JSONArray((cur + scopes).distinct().sorted())).also { it.remove("by") })
        own[id] = w; return w
    }
    fun scopesOf(e: JSONObject): Set<String> = (0 until e.getJSONArray("scopes").length()).map { e.getJSONArray("scopes").getString(it) }.toSet()
    @Synchronized fun end(by: String, id: String) {
        if (by == d.pub) {
            val e = own.remove(id)
            val until = (e?.opt("expiry") as? Number)?.toLong()?.plus(30 * 86400) ?: (now + 365 * 86400)
            if (ended.none { it.getString("id") == id }) ended += JSONObject().put("id", id).put("until", until)
            union["$by:$id"] = JSONObject().put("by", by).put("id", id).put("until", until)
        } else if (tombstones.none { it.getString("by") == by && it.getString("id") == id }) tombstones += JSONObject().put("by", by).put("id", id).put("at", now)
    }
    @Synchronized fun used(id: String) { lastUsed[id] = now }
    /** Every live grant on the account, for listing: newest per (by, id), never ended, never a non-device's. */
    @Synchronized fun all(): List<JSONObject> {
        val cur = current(); val out = LinkedHashMap<String, JSONObject>()
        fun consider(e: JSONObject, maker: String) {
            val by = e.optString("by"); if (by != maker || by !in cur || !Grants.entryOk(d.g, e)) return
            val k = "$by:${e.getString("id")}"
            if (k in union || tombstones.any { it.getString("by") == by && it.getString("id") == e.getString("id") }) return
            val p = out[k]; if (p == null || e.getInt("v") > p.getInt("v")) out[k] = e
        }
        for (e in own.values) consider(e, d.pub)
        for ((m, r) in others) if (m != d.pub) r.set.getJSONArray("entries").let { a -> for (i in 0 until a.length()) consider(a.getJSONObject(i), m) }
        return out.values.filter { !Grants.expired(it, now, lastUsed[it.getString("id")]) }
    }
    /** An own live grant for this site, door and connection (a grant applies only there). */
    @Synchronized fun forSite(site: String, door: String, connection: String? = null): JSONObject? = own.values.firstOrNull {
        it.getString("site") == site && it.getString("door") == door && (connection == null || it.getString("connection") == connection) &&
            !Grants.expired(it, now, lastUsed[it.getString("id")]) && "${it.getString("by")}:${it.getString("id")}" !in union
    }
    @Synchronized fun set(): JSONObject {
        val cur = current(); val t = now
        ended.removeAll { it.getLong("until") <= t }
        union.entries.removeAll { it.value.getLong("until") <= t || it.value.getString("by") !in cur }
        tombstones.removeAll { t - it.getLong("at") >= 30 * 86400 }
        return JSONObject().put("entries", JSONArray(own.values.filter { !Grants.expired(it, t, lastUsed[it.getString("id")]) }.sortedBy { it.getString("id") }))
            .put("tombstones", JSONArray(tombstones.toList())).put("ended", JSONArray(ended.toList())).put("union", JSONArray(union.values.sortedBy { "${it.getString("by")}:${it.getString("id")}" }))
    }
    /** Publish this device's grant event, signed by the account, under the current data key. */
    fun publish(net: RelayNet): List<JSONObject> {
        val at = maxOf(now, lastPublish + 1)
        val (state, key) = d.dataKey()
        val evs = Grants.events(d.g, d.sk, d.baseDataKey(), state, key, synchronized(this) { set() }, at)
        val signed = evs.map { u -> d.sign(u.kind, u.content, u.tags, u.createdAt) }
        synchronized(this) { lastPublish = at }
        for (e in signed) net.publishEvent(e)
        return signed
    }
    /** Read every current device's newest grant event (as TS `fetch`). */
    @Synchronized fun take(events: List<Event>) {
        val cur = current()
        for (m in cur) {
            val r = Grants.read(d.g, m, d.baseDataKey(), { s -> d.dataKeyFor(s) }, events) ?: continue
            if (m == d.pub) { adoptOwn(r); continue }
            val p = others[m]; if (p == null || r.at > p.at) others[m] = r
            r.set.getJSONArray("ended").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { x -> union["$m:${x.getString("id")}"] = JSONObject().put("by", m).put("id", x.getString("id")).put("until", x.getLong("until")) } }
            r.set.getJSONArray("union").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { u -> if (u.getString("by") in cur) union["${u.getString("by")}:${u.getString("id")}"] = u } }
            r.set.getJSONArray("tombstones").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { t -> if (t.getString("by") == d.pub && own.containsKey(t.getString("id"))) end(d.pub, t.getString("id")) } }
        }
        for (u in union.values.toList()) if (u.getString("by") == d.pub && own.containsKey(u.getString("id"))) end(d.pub, u.getString("id"))
    }
    private fun adoptOwn(r: Grants.Read) {
        r.set.getJSONArray("ended").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { x -> val id = x.getString("id")
            if (ended.none { it.getString("id") == id }) ended += x; own.remove(id); union["${d.pub}:$id"] = JSONObject().put("by", d.pub).put("id", id).put("until", x.getLong("until")) } }
        if (r.at <= lastPublish) return
        val there = (0 until r.set.getJSONArray("entries").length()).map { r.set.getJSONArray("entries").getJSONObject(it).getString("id") }.toSet()
        own.entries.removeAll { (id, e) -> e.getLong("made") < r.at && id !in there }
        r.set.getJSONArray("entries").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { e -> val mine = own[e.getString("id")]
            if (e.optString("by") == d.pub && Grants.entryOk(d.g, e) && (mine == null || e.getInt("v") > mine.getInt("v")) && "${d.pub}:${e.getString("id")}" !in union) own[e.getString("id")] = e } }
        lastPublish = r.at
    }
    @Synchronized fun dump(): JSONObject = JSONObject().put("own", JSONArray(own.values.toList())).put("tombstones", JSONArray(tombstones.toList())).put("ended", JSONArray(ended.toList()))
        .put("union", JSONArray(union.values.toList())).put("lastUsed", JSONArray(lastUsed.map { (k, v) -> JSONArray(listOf(k, v)) })).put("lastPublish", lastPublish)
    @Synchronized fun load(x: JSONObject?) {
        if (x == null) return
        own.clear(); x.optJSONArray("own")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { own[it.getString("id")] = it } }
        tombstones.clear(); x.optJSONArray("tombstones")?.let { a -> for (i in 0 until a.length()) tombstones += a.getJSONObject(i) }
        ended.clear(); x.optJSONArray("ended")?.let { a -> for (i in 0 until a.length()) ended += a.getJSONObject(i) }
        union.clear(); x.optJSONArray("union")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { union["${it.getString("by")}:${it.getString("id")}"] = it } }
        lastUsed.clear(); x.optJSONArray("lastUsed")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> lastUsed[p.getString(0)] = p.getLong(1) } }
        lastPublish = x.optLong("lastPublish")
    }
    @Synchronized fun clear() { own.clear(); tombstones.clear(); ended.clear(); union.clear(); others.clear(); lastUsed.clear() }
}
