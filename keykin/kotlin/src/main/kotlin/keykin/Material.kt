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
}
