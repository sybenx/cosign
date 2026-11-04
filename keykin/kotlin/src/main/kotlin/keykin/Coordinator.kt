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
        for (k in extra.keySet()) request.put(k, extra.get(k))
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
