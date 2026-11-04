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
        "unused-90d" -> now - maxOf(lastUsed ?: 0, e.optLong("last_used"), e.optLong("made")) > 90 * 86400
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
            val n = same[0].tag("parts")?.toIntOrNull() ?: 1
            if (n < 1 || n > 64) continue
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
            if (!schnorrVerify(x.optString("maker_sig"), setDigest(g, d, at, set), maker) || !shapeOk(set)) continue
            return Read(at, set)
        } catch (_: Exception) { /* a part we can't open, or a forgery: the next older one */ }
        return null
    }

    // --- which scope a request needs (§1), as TS ------------------------------------------------------
    val WALLET_KINDS = setOf(17375, 37375, 7375, 7376, 7374, 10019)
    /** Device policy §2's list and set kinds, exactly; the profile and relay lists count as lists here. */
    val LIST_KINDS = setOf(0, 3, 10000, 10002, 10050, 10001, 10003, 10004, 10005, 10006, 10007, 10009, 10012, 10013, 10015, 10020, 10030, 10063, 10101, 10102,
        30000, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30015, 30030, 39089)
    private fun tagOf(tags: List<List<String>>, n: String) = tags.firstOrNull { it.isNotEmpty() && it[0] == n }?.getOrNull(1)
    private fun hostOf(u: String?) = try { u?.let { java.net.URI(it).host?.lowercase()?.let { h -> if (java.net.URI(u).port >= 0) "$h:${java.net.URI(u).port}" else h } } } catch (_: Exception) { null }
    /** As TS `scopesForEvent`: every scope signing the event needs, or null for "declined" (a deletion by token,
     *  a token for no host). Another host than `ownHost` needs `host:<host>`, asked once per host (review 16 H1). */
    fun scopesForEvent(kind: Int, tags: List<List<String>> = emptyList(), ownHost: String? = null): List<String>? {
        if (kind == 22242) return listOf("sign-in")
        if (kind == 27235) {
            val method = (tagOf(tags, "method") ?: "").uppercase(); val host = hostOf(tagOf(tags, "u"))
            if (method == "DELETE" || host == null) return null
            val base = if (method == "PUT" || method == "PATCH") listOf("sign-in", "post") else listOf("sign-in")
            return if (host == ownHost) base else base + "host:$host"
        }
        if (kind == 24242) {
            val t = tagOf(tags, "t") ?: ""
            if (t == "delete") return null
            if (t in setOf("upload", "media", "get") && tags.count { it.isNotEmpty() && it[0] == "x" } == 1) return listOf("sign-in")
            val host = hostOf(tagOf(tags, "server")) ?: "any"
            return if (host == ownHost) listOf("sign-in") else listOf("sign-in", "host:$host")
        }
        return listOf(if (kind in WALLET_KINDS) "wallet" else if (kind in LIST_KINDS) "lists" else "post")
    }
    fun scopeForEvent(kind: Int) = if (kind in WALLET_KINDS) "wallet" else if (kind in LIST_KINDS) "lists" else if (kind == 22242) "sign-in" else "post"
    private val LIST_TAGS = setOf("p", "e", "a", "t", "r", "word", "emoji", "group", "relay")
    private val WALLET_FIELDS = setOf("privkey", "mint", "proofs", "direction", "amount", "unit", "balance")
    /** Parsed strictly (§9.5), as TS's JSON.parse reads valid JSON; null for anything else (review 16 L4). */
    private fun strict(text: String): Any? = try { Json.parse(text) } catch (_: Exception) { null }
    fun listPlaintextOk(plain: String): Boolean = (strict(plain) as? JSONArray)?.let { a -> (0 until a.length()).all { i ->
        (a.opt(i) as? JSONArray)?.let { t -> t.length() >= 1 && (0 until t.length()).all { t.opt(it) is String } && t.getString(0) in LIST_TAGS } == true } } ?: false
    fun looksWallet(plain: String): Boolean = when (val x = strict(plain)) {
        is JSONObject -> x.has("proofs") || x.has("mint") || x.has("privkey")
        is JSONArray -> (0 until x.length()).any { (x.opt(it) as? JSONArray)?.opt(0) in WALLET_FIELDS }
        else -> false
    }
    private val RANK = mapOf("private-data" to 3, "wallet" to 2, "lists" to 1, "dms" to 0)
    /** As TS `scopeForDecrypt` (Doors §1, "Which scope a decrypt needs"); "malformed" for a non-canonical payload. */
    fun scopeForDecrypt(g: String, peer: String, plaintext: String?, payload: String? = null, evidence: Evidence? = null, owner: String? = null): String {
        if (peer.lowercase() != g) return "dms"
        if (plaintext == null) return "private-data"
        val h = payload?.let { Evidence.hashOf(it) }
        if (payload != null && h == null) return "malformed"
        fun ofKind(k: Int) = if (k in WALLET_KINDS) "wallet" else if (k in LIST_KINDS) "lists" else if (k == 4 || k == 14) "dms" else "private-data"
        var need: String? = null
        if (h != null && evidence != null) {
            // Evidence: events whose ciphertext the same grant (or the member app) both encrypted and got signed.
            val vouched = evidence.vouched(h).map(::ofKind)
            val all = evidence.allKinds(h).map(::ofKind)
            if (vouched.isNotEmpty()) need = (vouched + all.filter { RANK[it]!! > RANK["lists"]!! }).maxByOrNull { RANK[it]!! }
            else if (evidence.owners[h].isNullOrEmpty() && all.isNotEmpty() && all.all { it == "lists" }) need = "lists"
        }
        if (need == "lists" && !listPlaintextOk(plaintext)) need = if (looksWallet(plaintext)) "wallet" else "private-data"
        if (need != null) return if (need == "private-data" && looksWallet(plaintext)) "wallet" else need
        (strict(plaintext) as? JSONObject)?.let { x -> if (x.opt("pubkey") == g && (x.opt("kind") as? Number)?.toInt() in setOf(14, 15, 7, 5)) return "dms" }
        return if (looksWallet(plaintext)) "wallet" else "private-data"
    }
    private val HEX16 = Regex("^[0-9a-f]{32}$"); private val HEX32 = Regex("^[0-9a-f]{64}$")
    /** A signed set still has to be a set (review 16 L2). */
    fun shapeOk(set: JSONObject): Boolean = try {
        fun arr(n: String) = set.getJSONArray(n).let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
        arr("entries").all { e -> HEX16.matches(e.optString("id")) && e.opt("v") is Number && HEX32.matches(e.optString("by")) && e.optJSONArray("scopes") != null && e.opt("site") is String } &&
            arr("tombstones").all { t -> fun whole(v: Any?) = (v is Int || v is Long) && (v as Number).toLong() >= 0
                // A wildcard (`*` with `before`) and a helper grant's `signer` are part of the shape (review 19 H1).
                HEX32.matches(t.optString("by")) && (HEX16.matches(t.optString("id")) || (t.optString("id") == "*" && whole(t.opt("before"))) || (t.optString("id") == "" && HEX32.matches(t.optString("signer"))))
                    && whole(t.opt("at")) && (!t.has("signer") || HEX32.matches(t.optString("signer"))) && (!t.has("before") || whole(t.opt("before"))) } &&
            arr("ended").all { HEX16.matches(it.optString("id")) && it.opt("until") is Number } &&
            arr("union").all { HEX32.matches(it.optString("by")) && HEX16.matches(it.optString("id")) && it.opt("until") is Number }
    } catch (_: Exception) { false }
}

/** What this device knows of the account's own ciphertexts (Device policy §1), as TS `Evidence`: by ciphertext
 *  hash, the events carrying it as `kind:signer`, and who encrypted it. An event is evidence only if the same grant
 *  (or the member app) both encrypted and signed it (review 17 M1). */
class Evidence {
    val kinds = LinkedHashMap<String, MutableSet<String>>()
    val owners = LinkedHashMap<String, MutableSet<String>>()
    /** Device policy §1's records (grant per event, deletions, removal logs, references), synced with these. */
    var ledger = Ledger()
    private val count = HashMap<String, Int>()
    companion object {
        const val PER_OWNER = 2000
        fun hashOf(payload: String): String? = try { val b = java.util.Base64.getDecoder().decode(payload); if (java.util.Base64.getEncoder().encodeToString(b) == payload) hex(sha(b)) else null } catch (_: Exception) { null }
    }
    @Synchronized fun encrypted(payload: String, owner: String) {
        val h = hashOf(payload) ?: return
        val s = owners.getOrPut(h) { LinkedHashSet() }; if (owner in s) return
        if (owner != "member" && (count[owner] ?: 0) >= PER_OWNER) { if (s.isEmpty()) owners.remove(h); return }
        s += owner; count[owner] = (count[owner] ?: 0) + 1; cap()
    }
    @Synchronized fun event(kind: Int, content: String, signer: String = "member") { hashOf(content)?.let { kinds.getOrPut(it) { LinkedHashSet() } += "$kind:$signer"; cap() } }
    @Synchronized fun vouched(h: String): List<Int> {
        val os = owners[h] ?: return emptyList()
        return (kinds[h] ?: emptySet<String>()).mapNotNull { x -> val i = x.indexOf(':'); if (i > 0 && x.substring(i + 1) in os) x.substring(0, i).toIntOrNull() else null }
    }
    @Synchronized fun allKinds(h: String): List<Int> = (kinds[h] ?: emptySet<String>()).mapNotNull { it.substringBefore(':').toIntOrNull() }
    @Synchronized fun trim(n: Int, now: Long? = null) { for (m in listOf<MutableMap<String, *>>(kinds, owners)) m.keys.take(n).toList().forEach { m.remove(it) }; if (now != null) ledger.trim(n, now) else ledger.trim(n); recount() }
    @Synchronized fun size() = kinds.size + owners.size + ledger.size()
    private fun recount() { count.clear(); for (os in owners.values) for (o in os) count[o] = (count[o] ?: 0) + 1 }
    private fun cap() { for (m in listOf<MutableMap<String, *>>(kinds, owners)) while (m.size > 20_000) m.remove(m.keys.first()) }
    @Synchronized fun dump(): JSONObject = JSONObject().put("kinds", JSONArray(kinds.map { (h, k) -> JSONArray(listOf(h, JSONArray(k.toList()))) })).put("owners", JSONArray(owners.map { (h, o) -> JSONArray(listOf(h, JSONArray(o.toList()))) })).put("ledger", ledger.data())
    @Synchronized fun load(x: JSONObject?) {
        kinds.clear(); owners.clear(); ledger = Ledger(); if (x == null) { recount(); return }
        ledger.take(x.optJSONObject("ledger")) { true }
        x.optJSONArray("kinds")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> kinds[p.getString(0)] = p.getJSONArray(1).let { k -> (0 until k.length()).map { j -> k.get(j).let { y -> if (y is Number) "${y.toInt()}:member" else y.toString() } }.toMutableSet() } } }
        x.optJSONArray("owners")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> owners[p.getString(0)] = p.getJSONArray(1).let { k -> (0 until k.length()).map { k.getString(it) }.toMutableSet() } } }
        recount()
    }
    @Synchronized fun clear() { kinds.clear(); owners.clear(); count.clear(); ledger.clear() }
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
    @Synchronized fun make(site: String, says: String, door: String, connection: String, scopes: List<String>, relays: List<String>? = null, signer: String? = null, helper: Boolean = false): JSONObject {
        val e = JSONObject().put("id", hex(ByteArray(16).also { SecureRandom().nextBytes(it) })).put("v", 1).put("site", site).put("says", says).put("door", door).put("connection", connection)
            .put("scopes", JSONArray(scopes.distinct().sorted())).put("borrowed", false).put("helper", helper).put("made", now).put("expiry", "unused-90d")
        relays?.let { e.put("relays", JSONArray(it)) }; signer?.let { e.put("signer", it) }
        val s = Grants.signEntry(d.g, d.sk, e); own[s.getString("id")] = s; dirty = true; return s
    }
    /** Own grants changed since the last publish (a publish that couldn't go out is retried at the next catch-up). */
    @Volatile var dirty = false
    /** Signer tombstones of own helper grants that ended, by any path, for the device to deliver to the helper (H2). */
    val helperEnds = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
    /** Whether the helper's latest report still lists this signer key (set by the device). */
    var helperLists: (String) -> Boolean = { false }
    @Synchronized fun widen(id: String, scopes: List<String>): JSONObject {
        val e = own[id] ?: refuse("unknown_grant")
        val cur = (0 until e.getJSONArray("scopes").length()).map { e.getJSONArray("scopes").getString(it) }
        val w = Grants.signEntry(d.g, d.sk, JSONObject(e.toString()).put("v", e.getInt("v") + 1).put("scopes", JSONArray((cur + scopes).distinct().sorted())).also { it.remove("by") })
        own[id] = w; dirty = true; return w
    }
    fun scopesOf(e: JSONObject): Set<String> = (0 until e.getJSONArray("scopes").length()).map { e.getJSONArray("scopes").getString(it) }.toSet()
    @Synchronized fun end(by: String, id: String) {
        dirty = true
        if (by == d.pub) {
            val e = own.remove(id)
            if (e?.optBoolean("helper") == true && e.has("signer") && helperEnds.none { it.optString("signer") == e.getString("signer") })
                helperEnds += JSONObject().put("by", by).put("id", id).put("at", now).put("signer", e.getString("signer"))
            val until = (e?.opt("expiry") as? Number)?.toLong()?.plus(30 * 86400) ?: (now + 365 * 86400)
            if (ended.none { it.getString("id") == id }) ended += JSONObject().put("id", id).put("until", until)
            union["$by:$id"] = JSONObject().put("by", by).put("id", id).put("until", until)
        } else if (tombstones.none { it.getString("by") == by && it.getString("id") == id }) {
            // A helper grant's tombstone names its signer key, which the helper's report carries too.
            val e = others[by]?.set?.getJSONArray("entries")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) }.firstOrNull { it.optString("id") == id } }
            tombstones += JSONObject().put("by", by).put("id", id).put("at", now).also { t -> if (e?.optBoolean("helper") == true && e.has("signer")) t.put("signer", e.getString("signer")) }
        }
    }
    /** The tombstone this device holds for (by, id). */
    @Synchronized fun tombstone(by: String, id: String): JSONObject? = tombstones.firstOrNull { it.getString("by") == by && it.getString("id") == id }
    @Synchronized fun tombstonesWithSigner(): List<JSONObject> = tombstones.filter { it.has("signer") }
    /** "Sign out of every site" for one home: here every own grant made before `before`; for another device a
     *  wildcard tombstone (`id: "*"`) it applies, any of its grants not yet published included. */
    @Synchronized fun endAll(home: String, before: Long): JSONObject? {
        if (home == d.pub) { for ((id, e) in own.toList()) if (e.getLong("made") < before) end(home, id); return null }
        tombstones.removeAll { it.getString("by") == home && it.getString("id") == "*" }
        return JSONObject().put("by", home).put("id", "*").put("at", now).put("before", before).also { tombstones += it }
    }
    /** Ends delivered to this device (or found in another device's event): its own grants they name end now. */
    @Synchronized fun takeEnds(ts: List<JSONObject>): List<String> {
        val gone = ArrayList<String>()
        for (t in ts) if (t.optString("by") == d.pub) {
            val id = t.optString("id"); val before = (t.opt("before") as? Number)?.toLong()
            // Two minutes' slack: `before` is the ending device's clock, `made` this one's (review 19 L1).
            if (id == "*" && before != null) { for ((x, e) in own.toList()) if (e.getLong("made") < before + 120) { end(d.pub, x); gone += x } }
            else if (own.containsKey(id)) { end(d.pub, id); gone += id }
        }
        return gone
    }
    /** Whether a tombstone or a wildcard (here or in any device's event) ends this entry. */
    private fun ends(e: JSONObject): Boolean {
        val by = e.optString("by"); val id = e.optString("id"); val made = e.optLong("made")
        fun hit(t: JSONObject) = t.optString("by") == by && (t.optString("id") == id || (t.optString("id") == "*" && (t.opt("before") as? Number)?.toLong()?.let { made < it } == true))
        return tombstones.any(::hit) || others.values.any { r -> r.set.getJSONArray("tombstones").let { a -> (0 until a.length()).any { hit(a.getJSONObject(it)) } } }
    }
    /** A use of an own grant: recorded, and once a day put in the entry (re-signed) for other devices' expiry (M4). */
    @Synchronized fun used(id: String) {
        lastUsed[id] = now
        val e = own[id] ?: return
        val day = now / 86400 * 86400
        if (e.optLong("last_used") < day) own[id] = Grants.signEntry(d.g, d.sk, JSONObject(e.toString()).put("last_used", day).also { it.remove("by") })
    }
    /** A use learnt elsewhere (the helper's report): the later wins, put in the entry once a day (review 19 H5). */
    @Synchronized fun usedAt(id: String, at: Long) {
        if ((lastUsed[id] ?: 0) >= at) return
        lastUsed[id] = at
        val e = own[id] ?: return
        val day = at / 86400 * 86400
        if (e.optLong("last_used") < day) { own[id] = Grants.signEntry(d.g, d.sk, JSONObject(e.toString()).put("last_used", day).also { it.remove("by") }); dirty = true }
    }
    @Synchronized fun lastUsedOf(id: String) = lastUsed[id]
    /** When a fetch last heard from more than half of the relays asked (§2: a publish follows a good fetch). */
    @Volatile var goodFetchAt = 0L
    private val publishing = Any()
    private fun unite(u: JSONObject) { val k = "${u.getString("by")}:${u.getString("id")}"; val p = union[k]; if (p == null || u.getLong("until") > p.getLong("until")) union[k] = u }
    /** Every live grant on the account, for listing: newest per (by, id), never ended, never a non-device's. */
    @Synchronized fun all(): List<JSONObject> {
        val cur = current(); val out = LinkedHashMap<String, JSONObject>()
        fun consider(e: JSONObject, maker: String) {
            val by = e.optString("by"); if (by != maker || by !in cur || !Grants.entryOk(d.g, e)) return
            val k = "$by:${e.getString("id")}"
            if (k in union || ends(e)) return
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
        // Kept 30 days, and longer while the maker still lists the entry (review 16 M8).
        // A wildcard while its home lists one made before it (review 19 M7); a helper grant's while the report lists it (H2).
        tombstones.removeAll { tb -> t - tb.getLong("at") >= 30 * 86400 && others.values.none { r -> r.set.getJSONArray("entries").let { a -> (0 until a.length()).any { a.getJSONObject(it).let { e -> e.optString("by") == tb.getString("by") &&
            (e.optString("id") == tb.getString("id") || (tb.optString("id") == "*" && e.optLong("made") < tb.optLong("before"))) } } } } && !(tb.has("signer") && helperLists(tb.getString("signer"))) }
        return JSONObject().put("entries", JSONArray(own.values.filter { !Grants.expired(it, t, lastUsed[it.getString("id")]) }.sortedBy { it.getString("id") }))
            .put("tombstones", JSONArray(tombstones.toList())).put("ended", JSONArray(ended.toList())).put("union", JSONArray(union.values.sortedBy { "${it.getString("by")}:${it.getString("id")}" }))
    }
    /** Publish this device's grant event, signed by the account, under the current data key. */
    fun publish(net: RelayNet): List<JSONObject> = synchronized(publishing) {
        // Before every publish a good fetch of its own newest event (review 19 M4).
        if (!try { fetchGood(net) } catch (_: Exception) { false }) refuse("try_later", "a grant fetch must reach most relays before a publish")
        val at = maxOf(now, lastPublish + 1)
        val (state, key) = d.dataKey()
        val evs = Grants.events(d.g, d.sk, d.baseDataKey(), state, key, synchronized(this) { set() }, at)
        val signed = evs.map { u -> d.sign(u.kind, u.content, u.tags, u.createdAt) }
        // Recorded before any part is sent, so a publish cut short never leaves it stuck (§2).
        synchronized(this) { lastPublish = at; lastSent = signed; counted = false; dirty = false }
        send(net, signed)
        signed
    }
    /** Relay health, the last event sent, the relays that took every part, and whether that counted (§2). */
    val relays = RelayHealth()
    @Volatile var lastSent: List<JSONObject> = emptyList(); private set
    @Volatile var lastSet: List<String> = emptyList(); private set
    @Volatile var lastSentAt = 0L; private set
    @Volatile var counted = false; private set
    private var countedKey = ""
    private var tries = 0
    @Volatile private var retrying = false
    /** Retries run here (tests run them at once). */
    var later: (Long, () -> Unit) -> Unit = { ms, f -> retry.schedule({ try { f() } catch (_: Exception) {} }, ms, java.util.concurrent.TimeUnit.MILLISECONDS) }
    private val retry = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "keykin-grant-retry").also { it.isDaemon = true } }
    /** Every part to the counted relays (and every configured one, which don't count); it counts once more than half
     *  of the writable counted relays accept every part, and is retried with back-off until then. */
    private fun send(net: RelayNet, parts: List<JSONObject>) {
        val recorded = d.recordedRelays()
        for (e in parts) net.publishEvent(e)
        if (recorded.isEmpty()) { counted = true; lastSentAt = now; return }
        val write = relays.writable(recorded, now)
        var took: Set<String>? = null
        for (e in parts) {
            val r = net.publishTo(e, write); relays.published(r, now)
            val ok = r.filter { it.value == true }.keys
            took = took?.intersect(ok) ?: ok
        }
        lastSet = took?.toList() ?: emptyList(); lastSentAt = now; countedKey = relays.counted(recorded).sorted().joinToString(" ")
        // Counted over the counted relays, a fetch-only one as not accepting (review 19 M1).
        if (RelayHealth.majority(lastSet, relays.counted(recorded))) { counted = true; tries = 0; return }
        // One retry pending at a time (L5).
        if (retrying) return
        retrying = true
        val delay = minOf(600_000L, 10_000L shl minOf(tries++, 6))
        later(delay) { retrying = false; if (lastSent === parts && !counted) send(net, parts) }
    }
    /** At each catch-up: the last event re-sent weekly, and to a majority of the new set when the counted relays change. */
    fun upkeep(net: RelayNet) {
        if (lastSent.isEmpty()) return
        val key = relays.counted(d.recordedRelays()).sorted().joinToString(" ")
        // Also an uncounted publish after a restart (its retry didn't survive it, review 19 M2).
        if (!counted || now - lastSentAt >= 7 * 86400 || (countedKey.isNotEmpty() && key != countedKey)) { counted = false; send(net, lastSent) }
    }
    /** A fetch from the counted relays: good once more than half of them answer, and more than half of the part of the
     *  last publish's set still counted (when three or more remain); with fewer than three counted, once one answers. */
    fun fetch(net: RelayNet): List<Event> = fetchEach(net).first
    private fun fetchGood(net: RelayNet): Boolean = fetchEach(net).second
    private fun fetchEach(net: RelayNet): Pair<List<Event>, Boolean> {
        val recorded = d.recordedRelays()
        // Only the current devices' grant events, by d and parts, so other app data can't crowd them out (review 19 M5).
        val ds = current().flatMap { m -> val dd = Grants.d(d.baseDataKey(), m); listOf(dd) + (1..64).map { "$dd:$it" } }
        val filter = JSONObject().put("kinds", JSONArray(listOf(Grants.KIND))).put("authors", JSONArray(listOf(d.g))).put("#d", JSONArray(ds))
        if (recorded.isEmpty()) { val (evs, a, n) = net.queryCounted(filter); take(evs, a, n); return evs to (n > 0 && a * 2 > n) }
        val ask = relays.toFetch(recorded, now)
        val (evs, answered) = net.queryEach(filter, ask)
        relays.fetched(ask, answered, recorded, now)
        val c = relays.counted(recorded); val still = lastSet.filter { it in c }
        val good = if (c.size < 3) answered.isNotEmpty() else RelayHealth.majority(answered, c) && (still.size < 3 || RelayHealth.majority(answered, still))
        take(evs, if (good) 1 else 0, 1)
        return evs to good
    }
    /** Read every current device's newest grant event (as TS `fetch`). */
    @Synchronized fun take(events: List<Event>, answered: Int = 1, asked: Int = 1) {
        if (asked > 0 && answered * 2 > asked) goodFetchAt = now
        val cur = current()
        for (m in cur) {
            val r = Grants.read(d.g, m, d.baseDataKey(), { s -> d.dataKeyFor(s) }, events) ?: continue
            if (m == d.pub) { adoptOwn(r); continue }
            val p = others[m]; if (p == null || r.at > p.at) others[m] = r
            r.set.getJSONArray("ended").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { x -> unite(JSONObject().put("by", m).put("id", x.getString("id")).put("until", x.getLong("until"))) } }
            r.set.getJSONArray("union").let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { u -> if (u.getString("by") in cur) unite(u) } }
            r.set.getJSONArray("tombstones").let { a -> takeEnds((0 until a.length()).mapNotNull { a.optJSONObject(it) }) }
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
        .put("others", JSONArray(others.map { (m, r) -> JSONArray(listOf(m, r.at, r.set)) }))
        .put("relays", relays.dump()).put("lastSent", JSONArray(lastSent)).put("lastSet", JSONArray(lastSet)).put("lastSentAt", lastSentAt).put("counted", counted)
        .put("countedKey", countedKey).put("tries", tries).put("dirty", dirty)
    @Synchronized fun load(x: JSONObject?) {
        if (x == null) return
        own.clear(); x.optJSONArray("own")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { own[it.getString("id")] = it } }
        tombstones.clear(); x.optJSONArray("tombstones")?.let { a -> for (i in 0 until a.length()) tombstones += a.getJSONObject(i) }
        ended.clear(); x.optJSONArray("ended")?.let { a -> for (i in 0 until a.length()) ended += a.getJSONObject(i) }
        union.clear(); x.optJSONArray("union")?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { union["${it.getString("by")}:${it.getString("id")}"] = it } }
        lastUsed.clear(); x.optJSONArray("lastUsed")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> lastUsed[p.getString(0)] = p.getLong(1) } }
        lastPublish = x.optLong("lastPublish")
        others.clear(); x.optJSONArray("others")?.let { a -> for (i in 0 until a.length()) a.getJSONArray(i).let { p -> others[p.getString(0)] = Grants.Read(p.getLong(1), p.getJSONObject(2)) } }
        relays.load(x.optJSONArray("relays"))
        lastSent = x.optJSONArray("lastSent")?.let { a -> (0 until a.length()).mapNotNull { a.optJSONObject(it) } } ?: emptyList()
        lastSet = x.optJSONArray("lastSet")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        lastSentAt = x.optLong("lastSentAt"); counted = x.optBoolean("counted")
        countedKey = x.optString("countedKey"); tries = x.optInt("tries"); dirty = x.optBoolean("dirty")
    }
    @Synchronized fun clear() { own.clear(); tombstones.clear(); ended.clear(); union.clear(); others.clear(); lastUsed.clear(); relays.clear(); lastSent = emptyList(); lastSet = emptyList() }
}
