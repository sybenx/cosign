// Upkeep on a device (core §6.7.1–§6.7.3, §7.2), as the TS reference's src/redeal.ts: a redeal's deltas
// checked against its commitments, the commitment at a state, the paper item a device verifies, and the
// new state. Pure apart from what it is given.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

/** A member's share state (§6.7.1): applied redeal ids, `C_S` and its shares. */
data class ShareState(val ids: Set<String>, val C: List<Pt?>, val shares: Map<Long, BigInteger>) {
    val hash: String get() = Codes.stateHash(ids.toList())
}

object Upkeep {
    fun dPoints(r: JSONObject): List<Pt> = r.getJSONArray("D").let { a -> (0 until a.length()).map { point(a.getString(it)) } }
    /** `δ(i)·G = Σ_k i^k·D_k`, k = 1..3. */
    fun deriveDelta(D: List<Pt>, i: BigInteger): Pt? { var acc: Pt? = null; var x = i.mod(N); for (d in D) { acc = add(acc, mul(x, d)); x = (x * i).mod(N) }; return acc }
    /** `C + D`: the constant term stays, `C_k += D_k`. */
    fun addRedeal(C: List<Pt?>, D: List<Pt>): List<Pt?> = C.mapIndexed { k, c -> if (k == 0) c else add(c, D[k - 1]) }
    /** The commitment at a set of applied redeals: `C0 + Σ D_r`. */
    fun commitmentAt(C0: List<Pt?>, redeals: List<JSONObject>): List<Pt?> = redeals.fold(C0) { c, r -> addRedeal(c, dPoints(r)) }
    /** The record's commitment at `ids`, every id a redeal of the view; refuses an unknown one. */
    fun commitmentAt(rec: JSONObject, view: MembershipView, ids: Collection<String>): List<Pt?> {
        val C0 = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
        return commitmentAt(C0, ids.sorted().map { view.redeals[it]?.r ?: refuse("unknown_redeal", it) })
    }

    /** §3.4: a member's own shares on `C`, and for a device, `C` rebuilt from `g` and its three points. */
    fun checkOwnShares(g: String, shares: Map<Long, BigInteger>, C: List<Pt?>, device: Boolean) {
        val G0 = liftXHex(g)
        if (C[0] != G0) refuse("bad_commitment", "C0 is not the group point")
        for ((i, s) in shares) if (mul(s) != derive(C, BigInteger.valueOf(i))) refuse("bad_share", "index $i")
        if (device) {
            if (shares.size != 3) refuse("bad_share", "a device holds 3 shares")
            val pts = listOf(BigInteger.ZERO to G0) + shares.map { (i, s) -> BigInteger.valueOf(i) to mul(s)!! }
            if (rebuild(pts) != C) refuse("bad_commitment", "the commitment does not rebuild from this device's points")
        }
    }

    /** Why a redeal can't be applied now, or null. */
    fun applicable(s: ShareState, r: JSONObject, abandoned: Set<String>): String? {
        val id = r.getString("id"); val base = strs(r.getJSONArray("base")); val ab = strs(r.getJSONArray("abandons"))
        if (id in s.ids) return "applied"
        if (id in abandoned || base.any { it in abandoned }) return "abandoned"
        if (base.any { it !in s.ids }) return "missing_base"
        if (ab.any { it in s.ids }) return "rerepair"
        return null
    }

    /** `L_j(x)` over `xs`. */
    private fun lagrangeAt(x: BigInteger, j: BigInteger, xs: List<BigInteger>): BigInteger {
        var num = BigInteger.ONE; var den = BigInteger.ONE
        for (k in xs) if (k != j) { num = (num * (x - k)).mod(N); den = (den * (j - k)).mod(N) }
        return (num * den.modInverse(N)).mod(N)
    }
    data class Applied(val state: ShareState, val paperValues: List<BigInteger>)
    /** §6.7.1 steps 1–3 for a device: every delta on `D`, the new shares on `C + D` (which rebuilds from
     *  this device's points), and the paper values `δ(b)` it keeps until the paper item is verified. */
    fun apply(g: String, s: ShareState, r: JSONObject, deltas: Map<Long, BigInteger>, backupSeat: List<Long>, abandoned: Set<String>): Applied {
        applicable(s, r, abandoned)?.let { refuse("cannot_apply", it) }
        val D = dPoints(r)
        if (deltas.keys != s.shares.keys) refuse("bad_redeal", "a delta for each index")
        for ((i, d) in deltas) if (mul(d) != deriveDelta(D, BigInteger.valueOf(i))) refuse("bad_delta", "index $i")
        val C = addRedeal(s.C, D)
        val shares = s.shares.mapValues { (i, v) -> (v + deltas.getValue(i)).mod(N) }
        checkOwnShares(g, shares, C, true)
        val xs = listOf(BigInteger.ZERO) + deltas.keys.map(BigInteger::valueOf)
        val paper = backupSeat.map { b -> deltas.entries.fold(BigInteger.ZERO) { acc, (i, d) -> (acc + d * lagrangeAt(BigInteger.valueOf(b), BigInteger.valueOf(i), xs)).mod(N) } }
        return Applied(ShareState(s.ids + r.getString("id"), C, shares), paper)
    }

    /** §6.7.2–§6.7.3: a delivery is sealed by its redeal's dealer, a device's carries the data-key seed,
     *  and every seed matches the hash the group-signed redeal pins. */
    fun checkDelivery(r: JSONObject, from: String, body: JSONObject, toDevice: Boolean) {
        if (from != r.getString("dealer")) refuse("not_dealer", "a delta comes only from its redeal's dealer")
        if (toDevice && !body.has("dk")) refuse("missing_seed", "a device's delivery carries the data-key seed")
        if (body.has("release") && hex(sha(unhex(body.getString("release")))) != r.getString("rs")) refuse("bad_seed", "release seed")
        if (body.has("dk") && hex(sha(unhex(body.getString("dk")))) != r.getString("dk")) refuse("bad_seed", "data-key seed")
    }

    /** §7.2: an item's hash, over the item without its `sig`. */
    fun itemHash(item: JSONObject): String = hex(sha(utf8(Jcs.of(JSONObject(item.toString()).also { it.remove("sig") }))))
    /** Open an item with its conversation key, under its release seed. */
    fun openItem(item: JSONObject, releaseSeed: String, ck: String): JSONObject {
        val inner = Json.utf8Strict(XChaCha.open(unhex(releaseSeed), unhex(item.getString("box"))))
        return Json.obj(Nip44.decrypt(inner, unhex(ck)))
    }
    /** §6.7.1 step 0: the redeal's pinned paper item, carrying `δ(b)` on `D` for the backup seat and the
     *  pinned data-key seed. True sets the "paper item verified" bit. */
    fun verifyPaperItem(r: JSONObject, item: JSONObject, releaseSeed: String, ck: String, backupSeat: List<Long>): Boolean = try {
        if (itemHash(item) != r.getString("paper_item") || item.optString("to") != r.getString("paper_to")) false
        else {
            val v = openItem(item, releaseSeed, ck); val D = dPoints(r)
            val b = v.getJSONArray("b").let { a -> (0 until a.length()).map { Json.long(a.get(it)) } }
            val d = v.getJSONArray("d")
            b == backupSeat && d.length() == b.size && b.indices.all { k -> mul(BigInteger(d.getString(k), 16)) == deriveDelta(D, BigInteger.valueOf(b[k])) } &&
                hex(sha(unhex(v.getString("dk_seed")))) == r.getString("dk")
        }
    } catch (_: Exception) { false }

    private fun strs(a: JSONArray) = (0 until a.length()).map { a.getString(it) }
}
