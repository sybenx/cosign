// The coordinator's side of a one-call signing round (core §5.1–§5.4) for the Kotlin device: its own
// commitments with hedged nonces (§5.2), kept in memory and used once; each partial checked against the
// co-signer's share points, naming the member whose partial fails; the result checked as BIP-340.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.SecureRandom

/** What a round needs of the account: `g`, the epoch, the state hash and the share points `C`. */
data class RoundContext(val g: String, val epochId: String, val state: String, val C: List<Pt?>)
data class Signer(val key: String, val indices: List<Long>)
/** An event before signing: NIP-01's fields without `id` and `sig`. */
data class Unsigned(val pubkey: String, val createdAt: Long, val kind: Int, val tags: List<List<String>>, val content: String) {
    val id: String get() = eventId(Event("", pubkey, createdAt, kind, tags, content, ""))
    /** As a coordinator sends it (§9.5): the six fields, `id` included. */
    fun wire(): JSONObject = JSONObject().put("pubkey", pubkey).put("created_at", createdAt).put("kind", kind)
        .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("id", id)
}

class OneCall(private val ctx: RoundContext, private val shares: Map<Long, BigInteger>, private val co: Signer, val event: Unsigned,
              extra: JSONObject = JSONObject(), cls: String = "sign") {
    val id: String = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    val eventId: String = event.id
    val request: JSONObject
    private var mine: List<Frost.Committed>?
    init {
        if (event.pubkey != ctx.g) refuse("wrong_pubkey")
        val signers = (shares.keys + co.indices).sorted()
        val context = unhex(eventId) + signers.fold(ByteArray(0)) { a, i -> a + u32(i) } + unhex(id) + unhex(co.key)
        mine = shares.keys.sorted().map { i -> Frost.commit(ctx.C, i, shares[i]!!, Frost.hedge(shares[i]!!, context)) }
        request = JSONObject().put("v", 1).put("type", "sign").put("g", ctx.g).put("epoch", ctx.epochId).put("id", id).put("cls", cls).put("state", ctx.state)
            .put("event", event.wire()).put("signers", JSONArray(signers)).put("commitments", JSONArray(mine!!.map { JSONObject().put("i", it.i).put("D", it.d).put("E", it.e) }))
        for (k in extra.keyList()) request.put(k, extra.get(k))
    }
    /** Finish with the co-signer's `partial`: the signed event as JSON, or a refusal naming the member. */
    fun finish(partial: JSONObject): JSONObject {
        val nonces = mine ?: refuse("used", "this round's nonces are spent")
        mine = null
        if (partial.optString("type") != "partial") refuse(partial.optString("code").ifEmpty { "no_partial" }, "from ${co.key.take(8)}")
        val theirs = (partial.optJSONArray("commitments") ?: JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it).let { c -> Frost.Committed(Json.long(c.get("i")), "", c.getString("D"), c.getString("E")) } } }
        if (theirs.map { it.i }.sorted() != co.indices.sorted()) refuse("bad_partial", "member ${co.key}")
        val all = nonces + theirs
        val zs = (partial.optJSONArray("z") ?: JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it).let { z -> Json.long(z.get("i")) to z.getString("z") } } }
        if (zs.map { it.first }.sorted() != co.indices.sorted()) refuse("bad_partial", "member ${co.key}")
        for ((i, z) in zs) if (!Frost.verifyShare(ctx.C, eventId, all, i, z)) refuse("bad_partial", "member ${co.key}")
        val own = nonces.map { it.i to Frost.sign(ctx.C, it, shares[it.i]!!, eventId, all) }
        val sig = Frost.aggregate(ctx.C, eventId, all, own + zs)
        val signed = event.wire().put("sig", sig)
        if (!verifyEvent(Event.of(signed))) refuse("bad_signature", "the aggregate does not verify")
        return signed
    }
    /** Discard the nonces (another co-signer answered first, §5.1). */
    fun abandon() { mine = null }
}

/** The coordinator's side of a two-call round (core §5.1–§5.2), as the TS reference's `TwoCall`: `commit` to every
 *  co-signer first, then `sign` with `after` and everyone's commitments; for one event or a list. A paper holder at a
 *  recovery (its backup seat plus two servers) signs this way, since no single co-signer reaches the threshold with it. */
class TwoCall(private val ctx: RoundContext, private val shares: Map<Long, BigInteger>, private val myIndices: List<Long>, private val cos: List<Signer>, val events: List<Unsigned>) {
    val commitId: String = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    val signId: String = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    private val ids = events.map { it.id }
    val signers: List<Long> = (myIndices + cos.flatMap { it.indices }).sorted()
    private var mine: List<List<Frost.Committed>>? = ids.map { evId -> myIndices.map { i ->
        Frost.commit(ctx.C, i, shares[i]!!, Frost.hedge(shares[i]!!, unhex(evId) + signers.fold(ByteArray(0)) { a, x -> a + u32(x) } + unhex(commitId) + utf8("two-call"))) } }
    private val theirs = HashMap<String, List<List<Frost.Committed>>>()
    private val isList get() = events.size > 1
    init { for (e in events) if (e.pubkey != ctx.g) refuse("wrong_pubkey") }
    private fun cj(c: Frost.Committed) = JSONObject().put("i", c.i).put("D", c.d).put("E", c.e)
    fun commitRequest(cls: String = "ask"): JSONObject = JSONObject().put("v", 1).put("type", "commit").put("g", ctx.g).put("epoch", ctx.epochId).put("id", commitId)
        .put("cls", cls).put("state", ctx.state).put("signers", JSONArray(signers)).also { if (isList) it.put("count", events.size) else it.put("event", events[0].wire()) }
    /** A co-signer's `commitments` answer (one set per event for a list). */
    fun took(co: String, answer: JSONObject) {
        if (answer.optString("type") != "commitments") refuse(answer.optString("code").ifEmpty { "no_commitments" }, co)
        fun set(a: JSONArray) = (0 until a.length()).map { a.getJSONObject(it).let { c -> Frost.Committed(Json.long(c.get("i")), "", c.getString("D"), c.getString("E")) } }
        theirs[co] = if (isList) answer.getJSONArray("sets").let { s -> (0 until s.length()).map { set(s.getJSONArray(it)) } } else listOf(set(answer.getJSONArray("commitments")))
    }
    private fun commitmentsFor(e: Int) = (mine ?: refuse("used"))[e] + cos.flatMap { theirs[it.key]?.get(e) ?: emptyList() }
    fun signRequest(cls: String = "ask", extra: JSONObject = JSONObject()): JSONObject {
        val r = JSONObject().put("v", 1).put("type", "sign").put("g", ctx.g).put("epoch", ctx.epochId).put("id", signId).put("cls", cls).put("state", ctx.state)
            .put("signers", JSONArray(signers)).put("after", commitId)
        for (k in extra.keyList()) r.put(k, extra.get(k))
        if (isList) r.put("list_events", JSONArray(events.indices.map { e -> JSONObject().put("event", events[e].wire()).put("commitments", JSONArray(commitmentsFor(e).map(::cj))) }))
        else r.put("event", events[0].wire()).put("commitments", JSONArray(commitmentsFor(0).map(::cj)))
        return r
    }
    /** Every co-signer's `partial`, checked against its share points; the signed events. */
    fun finishAll(partials: Map<String, JSONObject>): List<JSONObject> {
        val out = events.indices.map { e ->
            val all = commitmentsFor(e)
            val zs = ArrayList<Pair<Long, String>>()
            for (co in cos) {
                val p = partials[co.key]
                if (p == null || p.optString("type") != "partial") refuse(p?.optString("code")?.ifEmpty { null } ?: "no_partial", "member ${co.key}")
                val z = (if (isList) p.optJSONArray("events")?.optJSONObject(e)?.optJSONArray("z") else p.optJSONArray("z")) ?: JSONArray()
                val got = (0 until z.length()).map { z.getJSONObject(it).let { x -> Json.long(x.get("i")) to x.getString("z") } }
                if (got.map { it.first }.sorted() != co.indices.sorted()) refuse("bad_partial", "member ${co.key}")
                for ((i, zz) in got) { if (!Frost.verifyShare(ctx.C, ids[e], all, i, zz)) refuse("bad_partial", "member ${co.key}"); zs += i to zz }
            }
            for (n in mine!![e]) zs += n.i to Frost.sign(ctx.C, n, shares[n.i]!!, ids[e], all)
            val signed = events[e].wire().put("sig", Frost.aggregate(ctx.C, ids[e], all, zs))
            if (!verifyEvent(Event.of(signed))) refuse("bad_signature", "the aggregate does not verify")
            signed
        }
        mine = null
        return out
    }
}

/** The coordinator's side of a decryption (core §5.5): one co-signer's weighted answers, every proof
 *  checked, summed with this device's own weighted parts into `x·Q`. The own part is share arithmetic in
 *  the BigInteger reference curve: an Android build does it in libsecp256k1, as it does signing. */
object Ecdh {
    fun request(ctx: RoundContext, myIndices: List<Long>, co: Signer, points: List<String>): JSONObject =
        JSONObject().put("v", 1).put("type", "ecdh").put("g", ctx.g).put("epoch", ctx.epochId).put("id", hex(ByteArray(16).also { SecureRandom().nextBytes(it) }))
            .put("cls", "sign").put("state", ctx.state).put("points", JSONArray(points)).put("signers", JSONArray((myIndices + co.indices).sorted()))
    fun finish(ctx: RoundContext, req: JSONObject, shares: Map<Long, BigInteger>, co: Signer, answer: JSONObject): List<String> {
        if (answer.optString("type") != "ecdh_partial") refuse(answer.optString("code").ifEmpty { "no_answer" }, "member ${co.key}")
        val points = req.getJSONArray("points").let { a -> (0 until a.length()).map { a.getString(it) } }
        val signers = req.getJSONArray("signers").let { a -> (0 until a.length()).map { Json.long(a.get(it)) } }
        val answers = answer.optJSONArray("answers") ?: refuse("bad_answer", "one answer list per point")
        if (answers.length() != points.size) refuse("bad_answer", "one answer list per point")
        // A malformed answer is a bad answer, never a JSON error out of the decrypt (review 12 L1).
        try { return combine(ctx, signers, points, answers, shares, co) }
        catch (e: KeykinException) { throw e } catch (e: Exception) { refuse("bad_answer", "member ${co.key}: ${e.message}") }
    }
    private fun combine(ctx: RoundContext, signers: List<Long>, points: List<String>, answers: JSONArray, shares: Map<Long, BigInteger>, co: Signer): List<String> {
        return points.mapIndexed { q, Q ->
            val perQ = answers.getJSONArray(q).let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
            val got = perQ.map { Json.long(it.get("i")) }
            if (got.size != co.indices.size || got.toSet().size != got.size || !co.indices.all { it in got }) refuse("bad_answer", "indices must equal the member's indices exactly")
            for (a in perQ) if (!verifyDleq(ctx.g, ctx.epochId, ctx.state, signers, ctx.C, Q, Json.long(a.get("i")), a.getString("Y"), a.getString("R1"), a.getString("R2"), a.getString("z")))
                refuse("bad_proof", "index ${a.get("i")}")
            var acc: Pt? = null
            for (a in perQ) acc = add(acc, point(a.getString("Y")))
            for ((i, s) in shares) acc = add(acc, Keykin.secp.mulPoint(lagrange(BigInteger.valueOf(i), signers.map(BigInteger::valueOf)).multiply(s).mod(N), point(Q)))
            comp(acc ?: refuse("bad_answer", "the identity"))
        }
    }
}
