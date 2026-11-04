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
            for ((i, s) in shares) acc = add(acc, mul(lagrange(BigInteger.valueOf(i), signers.map(BigInteger::valueOf)).multiply(s).mod(N), point(Q)))
            comp(acc ?: refuse("bad_answer", "the identity"))
        }
    }
}
