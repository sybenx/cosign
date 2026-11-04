// A Kotlin device (step B1, growing): loaded from a device's state as the TS reference writes it
// (device/node.ts `snapshot()`), checked as core §4.4's handover step 2 says, and able to sign everyday
// events with any seated server over relays. Joins, changes and Upkeep follow.
package keykin

import org.json.JSONObject
import java.math.BigInteger

class Device(val sk: ByteArray, rec: JSONObject, val changes: List<Event>, val ids: List<String>, val shares: Map<Long, BigInteger>, private val net: RelayNet,
             private val baseDk: String = "", private val dkSeeds: List<String> = emptyList()) {
    val pub: String = Secp.Reference.pub(sk)
    val g: String = rec.getString("g"); val epochId: String = rec.getJSONObject("epoch").getString("id")
    val view: MembershipView = Membership.compute(rec, changes)
    val ctx: RoundContext
    init {
        // The share points at this state; a state after a redeal needs Upkeep's commitments (not yet ported).
        if (ids.isNotEmpty()) refuse("unsupported", "a state after a redeal")
        val C = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
        // §4.4 step 2: the key a current device holding exactly these indices, every share on C.
        val me = view.members.firstOrNull { it.key == pub }
        if (me == null || me.kind != "device" || me.shares.sorted() != shares.keys.sorted()) refuse("not_member", "not a current device holding exactly these indices")
        for ((i, s) in shares) if (mul(s) != derive(C, BigInteger.valueOf(i))) refuse("bad_share", "share $i is not on the commitments")
        ctx = RoundContext(g, epochId, Codes.stateHash(ids), C)
        net.host(sk, pub)
    }
    companion object {
        /** From a device's state as the TS reference writes it (device/node.ts `snapshot()`). */
        fun fromSnapshot(snapshot: String, net: RelayNet): Device {
            val x = Json.obj(snapshot)
            if (!Json.isInt(x.opt("v")) || Json.long(x.opt("v")) != 1L || x.optBoolean("wiped")) refuse("malformed", "not a live device snapshot")
            val recEv = Event.of(x.getJSONObject("recEv"))
            val rec = Record.check(recEv, recEv.pubkey)
            val ch = x.getJSONArray("changes"); val changes = (0 until ch.length()).map { Event.of(ch.getJSONObject(it)) }
            val st = x.getJSONObject("state"); val ids = (0 until st.getJSONArray("ids").length()).map { st.getJSONArray("ids").getString(it) }
            val sh = st.getJSONArray("shares")
            val shares = (0 until sh.length()).associate { sh.getJSONArray(it).let { p -> Json.long(p.get(0)) to BigInteger(p.getString(1), 16) } }
            val seeds = x.optJSONArray("dkSeeds")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
            return Device(unhex(x.getString("kp")), rec, changes, ids, shares, net, x.optString("baseDk"), seeds)
        }
        /** Join an account by its invite code (core §4.1–§4.2): hello, nonce, the 6-digit check shown by
         *  `onCheck`, then the welcome and the sigmas, checked. */
        fun join(code: String, net: RelayNet, onCheck: (String) -> Unit, timeoutMs: Long = 120_000): Device {
            val sk = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val pub = Secp.Reference.pub(sk)
            val j = Joiner(pub, null, net.now, parseCode(code))
            val welcome = java.util.concurrent.CompletableFuture<Pair<String, JSONObject>>()
            val sigmas = java.util.Collections.synchronizedList(ArrayList<JSONObject>())
            net.host(sk, pub) { from, body, _ ->
                when (body.optString("type")) {
                    "repair_sigma" -> { sigmas += JSONObject(body.toString()).put("from", from); JSONObject().put("type", "ack") }
                    "welcome" -> { welcome.complete(from to body); JSONObject().put("type", "ack") }
                    else -> null
                }
            }
            val (to, hello) = j.hello()
            val nonce = net.send(sk, to, hello)
            if (nonce.optString("type") != "join_nonce") refuse(nonce.optString("code").ifEmpty { "no_nonce" })
            j.onNonce(to, nonce)
            onCheck(j.check)
            val (from, w) = welcome.get(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            val r = j.finish(from, w, sigmas.toList())
            // The welcome carries the base data key and every data-key seed (core §4.2 step 4, §4.5).
            val seeds = w.optJSONArray("dk")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
            return Device(sk, r.rec, r.changes, r.ids, r.shares, net, w.optString("base_dk"), seeds)
        }
    }
    /** The data key (core §4.5), as device/datakey.ts gives it in TS: the key new data is written under,
     *  and the state hash it names. `dk(S) = HKDF("keykin-dk/1", base ‖ seeds of S, sorted)`. Only the
     *  epoch record's first state for now (states after a redeal come with Upkeep's port). */
    fun dataKey(): Pair<String, ByteArray> {
        if (!Regex("^[0-9a-f]{64}$").matches(baseDk)) refuse("no_data_key", "this device holds no data key")
        if (ids.isNotEmpty()) refuse("unsupported", "a state after a redeal")
        return Codes.stateHash(ids) to hkdf32(unhex(baseDk), utf8("keykin-dk/1"))
    }
    /** The seated servers, as members. */
    fun servers() = view.members.filter { it.kind == "server" }
    /** The x coordinate of `x·P` for a peer's x-only key (core §5.5), from one server's checked answer. */
    fun ecdhX(peer: String): ByteArray {
        var last = "no_server"
        for (s in servers()) {
            val co = Signer(s.key, s.shares)
            val req = Ecdh.request(ctx, shares.keys.sorted(), co, listOf("02$peer"))
            try { return unhex(Ecdh.finish(ctx, req, shares, co, net.send(sk, s.key, req))[0].substring(2)) } catch (e: KeykinException) { last = e.code }
        }
        refuse(last)
    }
    /** NIP-44 v2 as the account, with `peer`. */
    fun nip44(peer: String, text: String, encrypt: Boolean): String {
        val ck = hmac(utf8("nip44-v2"), ecdhX(peer))
        return if (encrypt) Nip44.encrypt(text, ck) else Nip44.decrypt(text, ck)
    }
    /** NIP-04 as the account, with `peer`: AES-256-CBC under the shared x. */
    fun nip04(peer: String, text: String, encrypt: Boolean): String {
        val key = javax.crypto.spec.SecretKeySpec(ecdhX(peer), "AES")
        val c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
        val b64 = java.util.Base64.getEncoder(); val d64 = java.util.Base64.getDecoder()
        if (encrypt) {
            val iv = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(iv))
            return b64.encodeToString(c.doFinal(utf8(text))) + "?iv=" + b64.encodeToString(iv)
        }
        val parts = text.split("?iv="); if (parts.size != 2) refuse("malformed", "nip04 payload")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(d64.decode(parts[1])))
        return Json.utf8Strict(c.doFinal(d64.decode(parts[0])))
    }

    /** Sign an event with the first server that gives a partial. */
    fun sign(kind: Int, content: String, tags: List<List<String>> = emptyList()): JSONObject {
        var last = "no_server"
        for (s in servers()) {
            val r = OneCall(ctx, shares, Signer(s.key, s.shares), Unsigned(g, net.now, kind, tags, content))
            val a = net.send(sk, s.key, r.request)
            if (a.optString("type") != "partial") { r.abandon(); last = a.optString("code").ifEmpty { "no_answer" }; continue }
            return r.finish(a)
        }
        refuse(last)
    }
}
