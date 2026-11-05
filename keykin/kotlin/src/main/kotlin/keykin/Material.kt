// A paper's material (core §4.3, §7.2; core 14.21 §4.5), as the TS reference's src/upkeep.ts: the base item (the backup
// seat's shares and the base data key, sealed to K, signed by K, under its release seed), the seed items (every
// data-key seed the printer holds, at most 1,000 per item, NIP-44 to K, signed by K, under the paper release seed), and
// the pin `inner` the paper change carries: SHA-256 over JCS of the base item's hash then the seed items' hashes.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

object Material {
    const val SEED_RECORDS_MAX = 1000
    private val rnd = SecureRandom()
    private fun signedByK(item: JSONObject, Ksk: ByteArray) = JSONObject(item.toString()).put("sig", Keykin.secp.schnorrSign(sha(utf8(Upkeep.itemHash(item))), Ksk, ByteArray(32).also(rnd::nextBytes)))

    /** The base item at creation or for a new paper: `{shares, dk, state}`, sealed to K, signed by K. */
    fun baseItem(Ksk: ByteArray, releaseSeed: String, shares: Map<Long, BigInteger>, baseDk: String, state: List<String>): JSONObject {
        val body = JSONObject().put("shares", JSONArray(shares.toSortedMap().map { (i, s) -> JSONArray(listOf(i, scalarHex(s))) })).put("dk", baseDk).put("state", JSONArray(state))
        val (item, _) = Deal.sealItem("base", null, Keykin.secp.pub(Ksk), releaseSeed, body)
        return signedByK(item, Ksk)
    }
    /** Records as base64 of binary `id (16 bytes) ‖ seed (32 bytes)`, sorted by id. */
    fun packSeeds(records: List<Pair<String, String>>): String {
        val sorted = records.sortedBy { it.first }
        val out = ByteArray(sorted.size * 48)
        sorted.forEachIndexed { k, (id, seed) -> unhex(id).copyInto(out, 48 * k); unhex(seed).copyInto(out, 48 * k + 16) }
        return Base64.getEncoder().encodeToString(out)
    }
    fun unpackSeeds(text: Any?): List<Pair<String, String>> {
        val b = Base64.getDecoder().decode(text as? String ?: refuse("bad_item", "seed records"))
        if (b.size % 48 != 0 || b.size / 48 > SEED_RECORDS_MAX) refuse("bad_item", "seed records")
        return (0 until b.size / 48).map { k -> hex(b.copyOfRange(48 * k, 48 * k + 16)) to hex(b.copyOfRange(48 * k + 16, 48 * k + 48)) }
    }
    /** A paper's seed items: every seed, at most 1,000 per item, under the paper release seed, signed by K. */
    fun seedItems(Ksk: ByteArray, paperReleaseSeed: String, records: List<Pair<String, String>>): List<JSONObject> =
        records.sortedBy { it.first }.chunked(SEED_RECORDS_MAX).map { chunk ->
            val (item, _) = Deal.sealItem("seeds", null, Keykin.secp.pub(Ksk), paperReleaseSeed, packSeeds(chunk))
            signedByK(item, Ksk)
        }
    /** The pin (`inner`). */
    fun inner(base: JSONObject, seeds: List<JSONObject>): String = hex(sha(utf8(Jcs.of(JSONArray(listOf(Upkeep.itemHash(base)) + seeds.map { Upkeep.itemHash(it) })))))
    /** Open seed items with K: their seeds, each kept only if it matches a co-signed redeal's `dk` (`dkOf`: id → dk). */
    fun openSeeds(items: List<JSONObject>, paperReleaseSeed: String, Ksk: ByteArray, dkOf: Map<String, String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (it in items) try {
            val inner = Json.utf8Strict(XChaCha.open(unhex(paperReleaseSeed), unhex(it.getString("box"))))
            val text = JSONArray("[" + Nip44.decrypt(inner, Nip44.conversationKey(Keykin.secp, Ksk, it.getString("eph"))) + "]").get(0)
            for ((id, seed) in unpackSeeds(text)) if (dkOf[id] == hex(sha(unhex(seed)))) out[id] = seed
        } catch (_: Exception) { /* an item that doesn't open costs only itself */ }
        return out
    }

    /** What a paper opens to at a recovery (core §6.5 step 4, 14.21): the backup seat's shares at the servers' state,
     *  that state's commitment, the base data key, and every data-key seed it can open. */
    class Opened(val shares: Map<Long, BigInteger>, val C: List<Pt?>, val dk: String, val dkSeeds: List<String>)
    /** As the TS reference's `openMaterial`: the base and K's seed items must match the pin (`inner`, or a pre-14.21
     *  base alone); the base opened under its release seed; then, for each redeal of `state` after the base's, the
     *  dealt item to K (or a re-issued one whose values match its clear values), whose `δ(b)` must lie on that redeal's
     *  commitments; the sums must lie on the state's commitment. `seeds`: each redeal's release seed (and "base"). */
    fun openMaterial(g: String, Ksk: ByteArray, pin: String, base: JSONObject, baseSeed: String, items: List<JSONObject>, seeds: Map<String, String>,
                     seedItemsIn: List<JSONObject>?, C0: List<Pt?>, redeals: List<JSONObject>, state: Set<String>): Opened {
        val K = Keykin.secp.pub(Ksk)
        fun signedByK(x: JSONObject) = try { schnorrVerify(x.optString("sig"), sha(utf8(Upkeep.itemHash(x))), K) } catch (_: Exception) { false }
        val seedIts = (seedItemsIn ?: items.filter { it.optString("kind") == "seeds" }).filter { it.optString("kind") == "seeds" && it.optString("to") == K && signedByK(it) }
        if (inner(base, seedIts) != pin && !(seedIts.isEmpty() && Upkeep.itemHash(base) == pin)) refuse("bad_material", "the base and seed items do not match their pin")
        if (!signedByK(base)) refuse("bad_material", "not signed by the backup key")
        val b = Upkeep.openItem(base, baseSeed, backupSk = Ksk)
        val shares = LinkedHashMap<Long, BigInteger>()
        b.getJSONArray("shares").let { a -> for (k in 0 until a.length()) a.getJSONArray(k).let { p -> shares[Json.long(p.get(0))] = BigInteger(p.getString(1), 16) } }
        val baseState = b.optJSONArray("state")?.let { a -> (0 until a.length()).map { a.getString(it) }.toSet() } ?: emptySet()
        val dkSeeds = ArrayList<String>()
        for (r in redeals.filter { it.getString("id") in state && it.getString("id") !in baseState }) {
            val id = r.getString("id")
            val seed = seeds[id] ?: refuse("missing_item", id)
            val cands = listOfNotNull(items.firstOrNull { it.opt("redeal") == id && it.optString("to") == K && Upkeep.itemHash(it) == r.optString("paper_item") }) +
                items.filter { it.opt("redeal") == id && it.optString("kind") == "reissue" && it.optString("to") == K }
            var v: JSONObject? = null
            val seat = shares.keys.sorted()
            for (it in cands) try {
                val x = Upkeep.openItem(it, seed, backupSk = Ksk)
                val bs = x.getJSONArray("b").let { a -> (0 until a.length()).map { Json.long(a.get(it)) } }
                val ds = x.getJSONArray("d").let { a -> (0 until a.length()).map { BigInteger(a.getString(it), 16) } }
                if (bs.sorted() != seat || ds.size != bs.size) continue
                val D = Upkeep.dPoints(r)
                if (!bs.indices.all { k -> mul(ds[k])?.let(::comp) == Upkeep.deriveDelta(D, BigInteger.valueOf(bs[k]))?.let(::comp) }) continue
                if (it.optString("kind") == "reissue") { val clear = it.optJSONArray("clear") ?: continue
                    if (ds.size != clear.length() || !ds.indices.all { k -> mul(ds[k])?.let(::comp) == clear.optString(k) }) continue }
                v = x; break
            } catch (_: Exception) { /* try the next */ }
            val got = v ?: refuse("missing_item", id)
            val bs = got.getJSONArray("b"); val ds = got.getJSONArray("d")
            for (k in 0 until bs.length()) { val i = Json.long(bs.get(k)); shares[i] = (shares[i]!! + BigInteger(ds.getString(k), 16)).mod(N) }
            // The data-key seed rides in the item, so a recovery loses no data (§4.5); checked against `dk`.
            (got.opt("dk_seed") as? String)?.let { sd -> if (hex(sha(unhex(sd))) == r.optString("dk")) dkSeeds += sd }
        }
        val C = Upkeep.commitmentAt(C0, redeals.filter { it.getString("id") in state })
        for ((i, sh) in shares) if (mul(sh)?.let(::comp) != derive(C, BigInteger.valueOf(i))?.let(::comp)) refuse("bad_material", "the sum misses P_$i")
        // Every seed of the seed items and every seed-only item it can open, each checked against its change's `dk`.
        val dkOf = redeals.associate { it.getString("id") to it.optString("dk") }
        for (sd in openSeeds(seedIts + items.filter { it.optString("kind") == "seed-only" && it.optString("to") == K }, baseSeed, Ksk, dkOf).values) if (sd !in dkSeeds) dkSeeds += sd
        return Opened(shares, C, b.getString("dk"), dkSeeds)
    }
}
