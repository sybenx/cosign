// Creating an account on this device by DKG (Account admin §1.1, core §4.3), as the TS reference's `createByDkg`, over
// real relays: each of three servers makes a throwaway DKG key signed by its host key; the three DKG rounds run among
// this device's five indices (three its own, two the paper's) and the servers' three, relayed by this device so every
// party sees the same packages; the servers enrol under the new group key `g`; the paper's base item seals the backup
// seat's shares under a creation release seed; this device signs the epoch record alone with four of its five shares
// (no co-signer knows the account yet), welcomes every server provisionally, then confirms. The backup seat's shares
// live only here until the paper is written down; a lockless device keeps the paper's secret until then (§4.3 step 4).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.SecureRandom

object Create {
    /** The new account's device, and its paper (secret and the 24 words to write down: never sent anywhere). */
    class Created(val device: Device, val paperSk: ByteArray, val words: List<String>, val signpost: String)

    private val S_IDX = listOf(4L, 7L, 8L); private val MINE = listOf(1L, 2L, 3L, 5L, 6L)
    private val ALL = (MINE + S_IDX).sorted()

    /** `fronts`: the three servers' front-door keys; `relays`: the account's relays (the record names them). */
    fun byDkg(net: RelayNet, fronts: List<String>, relays: List<String>, lock: Lock? = null): Created {
        if (fronts.size != 3) refuse("malformed", "three servers")
        val rnd = SecureRandom()
        val sk = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
        val pub = Keykin.secp.pub(sk)
        net.host(sk, pub)
        val addr = fronts.toMutableList()
        fun send(k: Int, body: JSONObject): JSONObject = net.send(sk, addr[k], body)
        // 1. Each server's throwaway DKG key, signed by its host key.
        val dkgKeys = JSONObject()
        for (k in addr.indices) {
            val a = send(k, JSONObject().put("type", "create"))
            if (a.optString("type") != "create_ok" || !schnorrVerify(a.optString("host_sig"), sha(utf8("keykin-dkg-key/1"), unhex(a.getString("dkg_key"))), a.optString("host"))) refuse("create_failed")
            dkgKeys.put(S_IDX[k].toString(), a.getString("dkg_key"))
        }
        // 2. Round 1, relayed by this device so everyone sees the same packages.
        val r1 = LinkedHashMap<Long, String>(); val secrets = HashMap<Long, String>()
        for (i in MINE) { val r = JSONObject(FrostNative.call("dkgPart1", idHex(i), ALL.size, 4, hex(ByteArray(32).also(rnd::nextBytes)))); r1[i] = r.getString("package"); secrets[i] = r.getString("secret") }
        for (k in addr.indices) r1[S_IDX[k]] = send(k, JSONObject().put("type", "dkg_1").put("index", S_IDX[k]).put("max", ALL.size)).getString("package")
        fun othersNum(i: Long) = JSONArray(r1.filterKeys { it != i }.map { (j, p) -> JSONArray(listOf(j, p)) })
        fun othersHex(i: Long) = JSONArray(r1.filterKeys { it != i }.map { (j, p) -> JSONArray(listOf(idHex(j), p)) }).toString()
        // 3. Round 2: packages to each holder (server-to-server ones sealed to the recipient's DKG key).
        // A package for another server comes back sealed to its DKG key (`{sealed, from}`) and is passed on as it is.
        val r2 = ALL.associateWith { HashMap<Long, Any>() }
        val s2 = HashMap<Long, String>()
        val byHex = ALL.associateBy { idHex(it) }
        for (i in MINE) {
            val r = JSONObject(FrostNative.call("dkgPart2", secrets[i]!!, othersHex(i))); s2[i] = r.getString("secret")
            val ps = r.getJSONArray("packages")
            for (x in 0 until ps.length()) ps.getJSONArray(x).let { p -> r2[byHex[p.getString(0)] ?: refuse("dkg", "a round-2 package for an unknown index")]!![i] = p.getString(1) }
        }
        secrets.clear()
        for (k in addr.indices) {
            val a = send(k, JSONObject().put("type", "dkg_2").put("round1", othersNum(S_IDX[k])).put("dkg_keys", dkgKeys))
            val ps = a.optJSONArray("packages") ?: refuse("dkg", "server ${k + 1}'s round 2: ${a.optString("code")}")
            for (x in 0 until ps.length()) ps.getJSONArray(x).let { p -> (r2[Json.long(p.get(0))] ?: refuse("dkg", "a round-2 package for an unknown index"))[S_IDX[k]] = p.get(1) }
        }
        // 4. Round 3: this device's shares, and the group key every server must agree on.
        val shares = HashMap<Long, BigInteger>(); var g = ""; var points = JSONArray()
        for (i in MINE) {
            val pkgs = JSONArray(r2[i]!!.map { (from, p) -> JSONArray(listOf(idHex(from), p as? String ?: refuse("dkg", "a sealed package for this device"))) }).toString()
            val out = JSONObject(FrostNative.call("dkgPart3", s2[i]!!, othersHex(i), pkgs))
            shares[i] = BigInteger(out.getString("share"), 16); g = out.getString("groupX"); points = out.getJSONArray("points")
        }
        s2.clear()
        for (k in addr.indices) {
            val a = send(k, JSONObject().put("type", "dkg_3").put("round1", othersNum(S_IDX[k])).put("round2", JSONArray(r2[S_IDX[k]]!!.map { (from, p) -> JSONArray(listOf(from, p)) })))
            if (a.optString("g") != g) refuse("dkg", "server ${k + 1} has another group key: ${a.optString("code").ifEmpty { a.optString("g").take(12) }}")
        }
        val pts = (0 until points.length()).map { points.getJSONArray(it) }.associate { BigInteger(it.getString(0), 16) to point(it.getString(1)) }
        val C = rebuild(listOf(BigInteger.ZERO to liftXHex(g)) + pts.keys.sorted().take(3).map { it to pts[it]!! })
        for ((i, p) in pts) if (derive(C, i) != p) refuse("dkg", "share point $i is off the polynomial")
        // 5. Enrol, now that g exists; from here on each seat is reached at its member key.
        val replies = ArrayList<JSONObject>()
        for (k in addr.indices) {
            val a = send(k, JSONObject().put("type", "enroll").put("g", g))
            if (a.optString("type") != "enroll_reply") refuse("enroll_failed")
            val reply = a.getJSONObject("reply"); addr[k] = reply.getString("member_key"); replies += reply
        }
        // 6. The paper and its base item: the backup seat's shares under the creation release seed.
        val paperSk = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
        val paper = Keykin.secp.pub(paperSk)
        val baseSeed = hex(ByteArray(32).also(rnd::nextBytes)); val baseDk = hex(ByteArray(32).also(rnd::nextBytes))
        val (sealed, _) = Deal.sealItem("base", null, paper, baseSeed, JSONObject().put("shares", JSONArray(listOf(5L, 6L).map { JSONArray(listOf(it, scalarHex(shares[it]!!))) })).put("dk", baseDk).put("state", JSONArray()))
        val base = JSONObject(sealed.toString()).put("sig", Keykin.secp.schnorrSign(sha(utf8(Upkeep.itemHash(sealed))), paperSk, ByteArray(32).also(rnd::nextBytes)))
        val epochId = hex(ByteArray(16).also(rnd::nextBytes))
        val members = JSONArray()
        members.put(JSONObject().put("key", pub).put("kind", "device").put("shares", JSONArray(listOf(1, 2, 3))).apply { lock?.let { put("lock", it.pub) } })
        for ((k, r) in replies.withIndex()) members.put(JSONObject().put("key", r.getString("member_key")).put("kind", "server").put("shares", JSONArray(listOf(S_IDX[k])))
            .put("host", r.opt("host")).put("operator", r.opt("operator")).put("own", false).put("https", r.opt("https")).put("relays", r.opt("relays")).put("vapid", r.opt("vapid")).put("enroll", r))
        members.put(JSONObject().put("key", paper).put("kind", "backup").put("shares", JSONArray(listOf(5, 6))))
        val rec = JSONObject().put("v", 1).put("g", g).put("epoch", JSONObject().put("n", 1).put("id", epochId)).put("prev", JSONObject.NULL).put("t", 4)
            .put("commitment", JSONArray(C.map { comp(it!!) })).put("role", "master").put("origin", "dkg").put("relays", JSONArray(relays)).put("members", members)
            .put("removed", JSONArray()).put("backup", hex(sha(utf8(Jcs.of(JSONArray(listOf(Upkeep.itemHash(base))))))))
            .put("seats", JSONObject().put("servers", JSONArray(S_IDX)).put("backup", JSONArray(listOf(5, 6))).put("helper", JSONArray(Codes.helperSeat(g))))
        // 7. This device signs the record alone with four of its five shares.
        val content = rec.toString(); val at = net.now
        val tags = listOf(listOf("d", "keykin"), listOf("v", "1"), listOf("epoch", "1"))
        val id = eventId(Event("", g, at, 30242, tags, content, ""))
        val signers = listOf(1L, 2L, 3L, 5L)
        val cs = signers.map { i -> Frost.commit(C, i, shares[i]!!, Frost.hedge(shares[i]!!, sha(unhex(id), utf8(i.toString())))) }
        val zs = cs.map { c -> c.i to Frost.sign(C, c, shares[c.i]!!, id, cs) }
        val sig = Frost.aggregate(C, id, cs, zs)
        val recEv = Event(id, g, at, 30242, tags, content, sig)
        if (!verifyEvent(recEv)) refuse("create_failed", "the record's signature")
        // 8. Welcome every server provisionally, then confirm once all adopted.
        val w = JSONObject().put("recEv", recEv.json()).put("changes", JSONArray()).put("state", JSONArray()).put("seeds", JSONArray().put(JSONArray(listOf("base", baseSeed))))
            .put("items", JSONArray()).put("base", base).put("provisional", true)
        for (k in addr.indices) { val a = send(k, JSONObject().put("type", "seat_welcome").put("w", w)); if (a.optString("type") != "ack") refuse(a.optString("code").ifEmpty { "welcome_failed" }) }
        val d = Device(sk, recEv, rec, emptyList(), emptyList(), listOf(1L, 2L, 3L).associateWith { shares[it]!! }, net, baseDk, emptyList())
        d.lock = lock
        d.takeWelcomeExtras(JSONObject().put("seeds", JSONArray().put(JSONArray(listOf("base", baseSeed)))).put("items", JSONArray()).put("base", base))
        if (lock == null) d.keepSecret(hex(paperSk))
        for (k in addr.indices) { val a = send(k, JSONObject().put("type", "confirm").put("epoch", epochId)); if (a.optString("type") != "ack") refuse(a.optString("code").ifEmpty { "confirm_failed" }) }
        // The signpost, published at creation (§6.7.5 route 3).
        // (A later device republishes a missing one.)
        val signpost = try { d.publishSignpost().getString("id") } catch (e: KeykinException) { "error: ${e.code}" }
        // The backup seat's shares were only ever here.
        shares.clear()
        return Created(d, paperSk, Backup.backupWords(paperSk), signpost)
    }
}
