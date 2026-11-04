// A Kotlin device as a list's dealer (core §6.1, §6.7.3, §6.7.6, §6.7.10), as the TS reference's
// src/approval.ts, src/lock.ts, src/redeal.ts `deal` and src/coordinator.ts `ListCall`: a lock approval,
// a redeal dealt with its sealed paper item, and every event of a list co-signed in one request.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec

const val KIND_CHANGE = 24302

/** A device's lock (§6.1), however it is held: an Android Keystore key with BIOMETRIC_STRONG, or `SoftLock`
 *  in tests. `pub` is `{pub, rp}` as the record and changes name it; `assert` gives a WebAuthn assertion
 *  `{authData, clientData, sig}` (base64url) over `what`. */
interface Lock {
    val pub: JSONObject
    fun assert(g: String, what: ByteArray): JSONObject
}

/** A software stand-in for a lock (tests only), the same as TS `softLock`: a P-256 key, `rpId`'s hash,
 *  user presence and verification set, a counter. A real lock's key never leaves its secure hardware. */
class SoftLock(val rpId: String, private val sk: ByteArray) : Lock {
    private val spec: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    private val priv = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, sk), spec))
    private var count = 0
    override val pub: JSONObject = run {
        val q = spec.generator.let { g -> p256Mul(BigInteger(1, sk), g.affineX, g.affineY) }
        JSONObject().put("pub", "04" + q.first.toString(16).padStart(64, '0') + q.second.toString(16).padStart(64, '0')).put("rp", hex(sha(utf8(rpId))))
    }
    @Synchronized override fun assert(g: String, what: ByteArray): JSONObject {
        val authData = sha(utf8(rpId)) + byteArrayOf(0x05) + u32((++count).toLong())
        val clientData = utf8(JSONObject().put("type", "webauthn.get").put("challenge", Codes.lockChallenge(g, what)).put("origin", "keykin:app").toString())
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(priv); update(authData + sha(clientData)) }.sign()
        return JSONObject().put("authData", b64u(authData)).put("clientData", b64u(clientData)).put("sig", b64u(sig))
    }
    companion object {
        private val P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
        private val A = P - BigInteger.valueOf(3)
        /** The public point, for `pub` only (JCA gives no way to derive it from a private key). */
        fun p256Mul(k: BigInteger, gx: BigInteger, gy: BigInteger): Pair<BigInteger, BigInteger> {
            var r: Pair<BigInteger, BigInteger>? = null; var q: Pair<BigInteger, BigInteger>? = gx to gy
            fun add(a: Pair<BigInteger, BigInteger>?, b: Pair<BigInteger, BigInteger>?): Pair<BigInteger, BigInteger>? {
                if (a == null) return b; if (b == null) return a
                val l = if (a == b) (BigInteger.valueOf(3) * a.first * a.first + A) * (BigInteger.TWO * a.second).modInverse(P)
                    else { if (a.first == b.first) return null; (b.second - a.second) * (b.first - a.first).modInverse(P) }
                val x = (l * l - a.first - b.first).mod(P); return x to (l * (a.first - x) - a.second).mod(P)
            }
            for (i in 0 until k.bitLength()) { if (k.testBit(i)) r = add(r, q); q = add(q, q) }
            return r!!
        }
        /** From what a TS snapshot keeps of a soft lock: `{soft: {rp, sk}}`. */
        fun fromStored(x: JSONObject?): SoftLock? = x?.optJSONObject("soft")?.let { SoftLock(it.getString("rp"), unhex(it.getString("sk"))) }
    }
}

object Approve {
    /** §6.1: what a lock signs for a list: `"change" ‖ H(placeholder list) ‖ epoch ‖ u64 expiry`. */
    fun changeWhat(list: JSONArray, epochId: String, expiry: Long): ByteArray = utf8("change") + unhex(Approvals.hash(list)) + unhex(epochId) + u64(expiry)
    fun lock(g: String, epochId: String, list: JSONArray, expiry: Long, member: String, lock: Lock): JSONObject =
        JSONObject().put("expiry", expiry).put("lock", JSONObject().put("member", member).put("assertion", lock.assert(g, changeWhat(list, epochId, expiry))))
}

/** Everything a dealer makes for one redeal (§6.7.3). The deltas live only here until the co-sign; call
 *  `destroy()` then or on any failure. */
class Dealt(val redeal: JSONObject, val deltas: MutableMap<String, Map<Long, BigInteger>>, val releaseSeed: String, val dkSeed: String, var paperEph: String, val paperItem: JSONObject, val paperValues: List<BigInteger>) {
    fun destroy() { deltas.clear(); paperEph = "" }
}

object Deal {
    private val rnd = SecureRandom()
    private fun scalar(): BigInteger { while (true) { val k = BigInteger(1, ByteArray(32).also(rnd::nextBytes)); if (k.signum() > 0 && k < N) return k } }
    private fun seed() = hex(ByteArray(32).also(rnd::nextBytes))

    /** XChaCha20-Poly1305 under a release seed (§7.2): `nonce ‖ ciphertext ‖ tag`. */
    fun wrapUnder(seed: String, plain: ByteArray): ByteArray = XChaCha.seal(unhex(seed), ByteArray(24).also(rnd::nextBytes), plain)
    /** One material item (§7.2): sealed to the backup key K (NIP-44 from a fresh key), wrapped under a release seed. */
    /** Returns the item and its ephemeral secret (hex): devices get it as `paper_eph` / `reissue_eph` and derive
     *  the conversation key themselves, exactly as K will from its side (core 14.20). */
    fun sealItem(kind: String, redeal: String?, K: String, releaseSeed: String, body: JSONObject): Pair<JSONObject, String> {
        val eph = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
        val ck = Nip44.conversationKey(Keykin.secp, eph, K)
        val inner = Nip44.encrypt(Jcs.of(body), ck)
        val item = JSONObject().put("kind", kind).put("redeal", redeal ?: JSONObject.NULL).put("to", K).put("eph", Keykin.secp.pub(eph)).put("box", hex(wrapUnder(releaseSeed, utf8(inner))))
        val out = hex(eph); eph.fill(0); ck.fill(0)
        return item to out
    }

    /** Deal a redeal for the post-change view (§6.7.3): `members` maps each recipient's key to its indices
     *  (devices, seat holders and incoming ones; never the backup, never a removed key). */
    fun deal(g: String, dealerSk: ByteArray, base: Collection<String>, members: Map<String, List<Long>>, paperTo: String, backupSeat: List<Long>, abandons: List<String> = emptyList()): Dealt {
        val d = listOf(scalar(), scalar(), scalar())
        fun f(x: Long): BigInteger { val xi = BigInteger.valueOf(x); var acc = BigInteger.ZERO; var p = xi; for (c in d) { acc = (acc + c * p).mod(N); p = (p * xi).mod(N) }; return acc }
        val D = d.map { mul(it)!! }
        val deltas = members.mapValues { (_, idx) -> idx.associateWith(::f) }.toMutableMap()
        val releaseSeed = seed(); val dkSeed = seed()
        val id = hex(ByteArray(16).also(rnd::nextBytes))
        val paper = backupSeat.map(::f)
        val (item, eph) = sealItem("paper", id, paperTo, releaseSeed, JSONObject().put("redeal", id).put("d", JSONArray(paper.map(::scalarHex))).put("b", JSONArray(backupSeat)).put("dk_seed", dkSeed))
        val r = JSONObject().put("id", id).put("dealer", Keykin.secp.pub(dealerSk)).put("D", JSONArray(D.map(::comp))).put("paper_to", paperTo)
            .put("paper_item", Upkeep.itemHash(item)).put("dk", hex(sha(unhex(dkSeed)))).put("rs", hex(sha(unhex(releaseSeed))))
            .put("base", JSONArray(base.sorted())).put("abandons", JSONArray(abandons.sorted()))
        r.put("sig", Keykin.secp.schnorrSign(Approvals.detached("redeal", g, Json.obj(Jcs.of(r))), dealerSk, ByteArray(32).also(rnd::nextBytes)))
        return Dealt(r, deltas, releaseSeed, dkSeed, eph, item, paper)
    }

    /** The post-change view of a list (§6.7.3): who gets deltas. Never an outgoing seat holder, never a
     *  member the list removes, never the backup (it gets the paper item); incoming seat holders are in. */
    fun postListView(v: MembershipView, list: JSONArray): Map<String, Member> {
        val out = LinkedHashMap(v.members.filter { it.kind != "backup" }.associateBy { it.key })
        for (k in 0 until list.length()) {
            val c = list.getJSONObject(k)
            if (c.has("remove")) out.remove(c.getString("remove"))
            c.optJSONObject("seat")?.let { s ->
                v.seats[s.getString("seat")]?.let { out.remove(it) }
                s.optJSONObject("new")?.let { n -> out[n.getString("key")] = member(n) }
            }
        }
        return out
    }
    /** The backup key current after the list (`paper_to`). */
    fun postListBackup(v: MembershipView, list: JSONArray): String =
        (0 until list.length()).map { list.getJSONObject(it) }.firstOrNull { it.has("paper") }?.getJSONObject("paper")?.getString("key") ?: v.backup ?: refuse("no_backup")
}

/** One-call round for a whole list (§6.7.10): every event in one `sign`, each with its own nonces. */
class ListCall(private val ctx: RoundContext, private val shares: Map<Long, BigInteger>, private val co: Signer, val events: List<Unsigned>, extra: JSONObject = JSONObject()) {
    val id: String = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    val request: JSONObject
    private val ids = events.map { it.id }
    private var mine: List<List<Frost.Committed>>?
    init {
        if (events.any { it.pubkey != ctx.g }) refuse("wrong_pubkey")
        val signers = (shares.keys + co.indices).sorted()
        mine = ids.map { evId ->
            val context = unhex(evId) + signers.fold(ByteArray(0)) { a, i -> a + u32(i) } + unhex(id) + unhex(co.key)
            shares.keys.sorted().map { i -> Frost.commit(ctx.C, i, shares[i]!!, Frost.hedge(shares[i]!!, context)) }
        }
        request = JSONObject().put("v", 1).put("type", "sign").put("g", ctx.g).put("epoch", ctx.epochId).put("id", id).put("cls", "ask").put("state", ctx.state)
            .put("signers", JSONArray(signers))
            .put("list_events", JSONArray(events.mapIndexed { e, ev -> JSONObject().put("event", ev.wire()).put("commitments", JSONArray(mine!![e].map { JSONObject().put("i", it.i).put("D", it.d).put("E", it.e) })) }))
        for (k in extra.keyList()) request.put(k, extra.get(k))
    }
    fun finish(partial: JSONObject): List<JSONObject> {
        val nonces = mine ?: refuse("used", "this round's nonces are spent")
        mine = null
        val evs = partial.optJSONArray("events")
        if (partial.optString("type") != "partial" || evs == null || evs.length() != events.size) refuse(partial.optString("code").ifEmpty { "no_partial" }, "from ${co.key.take(8)}")
        return try {
            events.mapIndexed { e, ev ->
                val pe = evs.getJSONObject(e)
                val theirs = (pe.optJSONArray("commitments") ?: JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it).let { c -> Frost.Committed(Json.long(c.get("i")), "", c.getString("D"), c.getString("E")) } } }
                val zs = (pe.optJSONArray("z") ?: JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it).let { z -> Json.long(z.get("i")) to z.getString("z") } } }
                if (theirs.map { it.i }.sorted() != co.indices.sorted() || zs.map { it.first }.sorted() != co.indices.sorted()) refuse("bad_partial", "member ${co.key}")
                val all = nonces[e] + theirs
                for ((i, z) in zs) if (!Frost.verifyShare(ctx.C, ids[e], all, i, z)) refuse("bad_partial", "member ${co.key}")
                val own = nonces[e].map { it.i to Frost.sign(ctx.C, it, shares[it.i]!!, ids[e], all) }
                val signed = ev.wire().put("sig", Frost.aggregate(ctx.C, ids[e], all, own + zs))
                if (!verifyEvent(Event.of(signed))) refuse("bad_signature", "the aggregate does not verify")
                signed
            }
        } catch (x: KeykinException) { throw x } catch (x: Exception) { refuse("bad_partial", "member ${co.key}: ${x.message}") }
    }
    fun abandon() { mine = null }
}
