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
        return commitmentAt(C0, ids.toSortedSet().map { view.redeals[it]?.r ?: refuse("missing_redeal", it) })
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
        // And the release seed: without it the device could neither re-issue nor read the item (review 14 M2).
        if (toDevice && !body.has("release")) refuse("missing_seed", "a device's delivery carries the release seed")
        fun seed(f: String) = (body.opt(f) as? String)?.takeIf { HEX32.matches(it) } ?: refuse("bad_seed", "$f: 32 bytes of hex")
        if (body.has("release") && hex(sha(unhex(seed("release")))) != r.getString("rs")) refuse("bad_seed", "release seed")
        if (body.has("dk") && hex(sha(unhex(seed("dk")))) != r.getString("dk")) refuse("bad_seed", "data-key seed")
    }

    /** §7.2: an item's hash, over the item without its `sig`. */
    fun itemHash(item: JSONObject): String = hex(sha(utf8(Jcs.of(JSONObject(item.toString()).also { it.remove("sig") }))))
    /** Open an item under its release seed, with the conversation key derived from its ephemeral secret
     *  towards its `to` (core 14.20: never a key taken from the sender), or from K's secret towards its `eph`. */
    fun openItem(item: JSONObject, releaseSeed: String, ephSk: String? = null, backupSk: ByteArray? = null): JSONObject {
        val inner = Json.utf8Strict(XChaCha.open(unhex(releaseSeed), unhex(item.getString("box"))))
        val ck = if (ephSk != null) Nip44.conversationKey(Keykin.secp, unhex(ephSk), item.getString("to")) else Nip44.conversationKey(Keykin.secp, backupSk!!, item.getString("eph"))
        return Json.obj(Nip44.decrypt(inner, ck))
    }
    /** Core 14.20 §6.7.1 step 0 (and §6.7.6 for a re-issued item), as TS `checkItem`: "missing" when `pe` isn't
     *  bound to this redeal and item (or isn't the item's key), which proves nothing; "bad" when a bound one
     *  doesn't open the item or opens it to other contents than `own` (proof against the sealer); "ok". `own`
     *  null: no own values to compare. `pinned`: the hash the redeal pins (the dealer's item, to `paper_to`). */
    fun checkItem(r: JSONObject, item: JSONObject?, releaseSeed: String, pe: JSONObject?, own: Triple<List<Long>, List<BigInteger>, String>?, backupSeat: List<Long>, pinned: String? = null): String {
        if (item == null || pe == null || pe.opt("redeal") != r.getString("id") || item.opt("redeal") != r.getString("id")) return "missing"
        val eph = pe.opt("eph") as? String ?: return "missing"
        val h = try { itemHash(item) } catch (_: Exception) { return "missing" }
        if (pe.opt("item") != h) return "missing"
        if (pinned != null && (pinned != h || item.opt("to") != r.getString("paper_to"))) return "missing"
        if (!HEX32.matches(eph) || try { Keykin.secp.pub(unhex(eph)) != item.opt("eph") } catch (_: Exception) { true }) return "missing"
        val v = try { openItem(item, releaseSeed, ephSk = eph) } catch (_: Exception) { return "bad" }
        return try {
            val D = dPoints(r)
            val b = v.getJSONArray("b").let { a -> (0 until a.length()).map { Json.long(a.get(it)) } }
            val d = v.getJSONArray("d").let { a -> (0 until a.length()).map { scalar(a.get(it)) } }
            val dk = v.opt("dk_seed") as? String
            when {
                v.opt("redeal") != r.getString("id") || b != backupSeat || d.size != b.size -> "bad"
                !b.indices.all { k -> mul(d[k]) == deriveDelta(D, BigInteger.valueOf(b[k])) } -> "bad"
                dk == null || hex(sha(unhex(dk))) != r.getString("dk") -> "bad"
                own != null && (own.first != backupSeat || own.second != d || own.third != dk) -> "bad"
                else -> "ok"
            }
        } catch (_: Exception) { "bad" }
    }

    /** §6.7.6 re-issue: the paper values this device kept for a redeal, sealed to the current backup key K
     *  under that redeal's release seed, with `δ(b)·G` in the clear, signed by this device's member key as
     *  `detached("paper-reissue", item without its sig)` (core 14.19 §5.9). K learns only what devices know. */
    /** Returns the item and its ephemeral secret, which the other devices get as `reissue_eph` (core 14.20). */
    fun reissueItem(g: String, r: JSONObject, K: String, kept: JSONObject, sk: ByteArray): Pair<JSONObject, String> {
        val d = kept.getJSONArray("d").let { a -> (0 until a.length()).map { scalar(a.get(it)) } }
        val body = JSONObject().put("redeal", r.getString("id")).put("d", JSONArray(d.map(::scalarHex))).put("b", kept.getJSONArray("b")).put("dk_seed", kept.getString("dk"))
        val (item, eph) = Deal.sealItem("reissue", r.getString("id"), K, kept.getString("release"), body)
        item.put("clear", JSONArray(d.map { comp(mul(it)!!) })).put("by", Keykin.secp.pub(sk))
        return item.put("sig", Keykin.secp.schnorrSign(Approvals.detached("paper-reissue", g, Json.obj(Jcs.of(item))), sk, ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })) to eph
    }
    /** §6.7.6: what a server checks of a re-issued item, as TS `checkReissue`; null, or the refusal. */
    fun checkReissue(g: String, r: JSONObject, item: JSONObject, K: String, isDevice: (String) -> Boolean, backupSeat: List<Long>): String? = try {
        val by = item.opt("by") as? String
        val clear = item.optJSONArray("clear")
        val D = dPoints(r)
        when {
            item.opt("kind") != "reissue" || item.opt("redeal") != r.getString("id") -> "bad_item"
            item.opt("to") != K -> "not_current_backup"
            by == null || !isDevice(by) -> "not_device"
            !schnorrVerify(item.optString("sig"), Approvals.detached("paper-reissue", g, Json.obj(Jcs.of(JSONObject(item.toString()).also { it.remove("sig") }))), by) -> "bad_signature"
            clear == null || clear.length() != backupSeat.size || !backupSeat.indices.all { k -> clear.getString(k) == comp(deriveDelta(D, BigInteger.valueOf(backupSeat[k]))!!) } -> "bad_clear"
            else -> null
        }
    } catch (_: Exception) { "bad_item" }
    private val HEX32 = Regex("^[0-9a-f]{64}$")
    /** A scalar as §9.5 writes it: 64 lowercase hex, below N (TS `scalarFrom`). */
    fun scalar(h: Any?): BigInteger {
        val s = (h as? String)?.takeIf { HEX32.matches(it) } ?: refuse("malformed", "a scalar is 64 lowercase hex")
        return BigInteger(s, 16).also { if (it >= N) refuse("malformed", "a scalar is below N") }
    }
    private fun strs(a: JSONArray) = (0 until a.length()).map { a.getString(it) }
}
