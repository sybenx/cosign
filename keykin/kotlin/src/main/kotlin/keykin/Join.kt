// Joining (core §4.1–§4.2) for the Kotlin device: the codes, the typed check, and the new device's checks
// on its welcome, as the TS reference's join.ts `Joiner`. A joining member trusts only what it scanned,
// the group key and the check both screens show (live finding #17).
package keykin

import org.json.JSONObject
import java.math.BigInteger
import java.net.URLDecoder
import java.security.SecureRandom

const val CODE_TTL_S = 600L

data class Code(val kind: String, val g: String?, val m: String?, val n: String?, val s: String, val x: Long, val r: List<String>)

/** Read a code; `cosign:` is accepted in place of `keykin:` (§11.3). `s` is base64url on the wire. */
fun parseCode(code: String): Code {
    val m = Regex("^(keykin|cosign):(join|hello)\\?(.*)$").matchEntire(code.trim()) ?: refuse("bad_code")
    val q = m.groupValues[3].split("&").filter { it.isNotEmpty() }.map { it.split("=", limit = 2).let { kv -> kv[0] to URLDecoder.decode(kv.getOrElse(1) { "" }, "UTF-8") } }
    fun one(k: String) = q.firstOrNull { it.first == k }?.second
    val x = one("x")?.takeIf { Regex("^(0|[1-9][0-9]{0,15})$").matches(it) }?.toLong() ?: refuse("bad_code", "x")
    val s = hex(b64d(one("s") ?: ""))
    if (s.length != 32) refuse("malformed", "s")
    fun k32(v: String?, what: String) = v?.takeIf { Regex("^[0-9a-f]{64}$").matches(it) } ?: refuse("malformed", what)
    val r = q.filter { it.first == "r" }.map { it.second }
    return if (m.groupValues[2] == "join") Code("join", k32(one("g"), "g"), k32(one("m"), "m"), null, s, x, r)
    else Code("hello", null, null, k32(one("n"), "n"), s, x, r)
}

class Joiner(val n: String, val lock: JSONObject?, now: Long, scanned: Code?) {
    var g: String? = null; var m: String? = null; var s: String; var x: Long
    var helloTo: String? = null; var t: String? = null
    init {
        if (scanned != null) {
            if (scanned.kind != "join") refuse("bad_code")
            if (scanned.x < now) refuse("expired")
            g = scanned.g; m = scanned.m; s = scanned.s; x = scanned.x
        } else { s = hex(ByteArray(16).also { SecureRandom().nextBytes(it) }); x = now + CODE_TTL_S }
    }
    /** Invite direction: the hello, sealed to the invite's `m`. */
    fun hello(): Pair<String, JSONObject> { helloTo = m; return m!! to JSONObject().put("type", "join_hello").put("n", n).put("s", s).put("lock", lock ?: JSONObject.NULL) }
    fun onNonce(from: String, msg: JSONObject) {
        if (from != helloTo) refuse("wrong_sender", "a join_nonce only from the key the hello went to")
        if (t != null) refuse("already_accepted")
        val tt = msg.opt("t") as? String ?: refuse("malformed", "t")
        if (!Regex("^[0-9a-f]{32}$").matches(tt)) refuse("malformed", "t")
        t = tt
    }
    /** The 6 digits this screen shows. */
    val check: String get() = Codes.joinCheck(g!!, m!!, n, s, t ?: refuse("no_nonce"))

    data class Joined(val rec: JSONObject, val recEv: Event, val changes: List<Event>, val view: MembershipView, val shares: Map<Long, BigInteger>, val C: List<Pt?>, val ids: List<String>)
    /** §4.2 step 5: the welcome sealed by `m`, its record and changes checked, a valid add of this key with
     *  this lock, and each share from exactly the inviter's sigma and one server's. */
    fun finish(from: String, welcome: JSONObject, sigmas: List<JSONObject>): Joined {
        if (from != m) refuse("not_sealed_by_m", "a welcome from a stranger")
        val recEv = Event.of(welcome.getJSONObject("record"))
        val rec = Record.check(recEv, g!!)
        val ch = welcome.getJSONArray("changes"); val changes = (0 until ch.length()).map { Event.of(ch.getJSONObject(it)) }
        val view = Membership.compute(rec, changes)
        if (view.invariant) refuse("invariant")
        val me = view.members.firstOrNull { it.key == n }
        if (me == null || me.kind != "device") refuse("no_add", "no valid change adds this key")
        if (Jcs.of(me.lock ?: JSONObject.NULL) != Jcs.of(lock ?: JSONObject.NULL)) refuse("no_add", "the add names another lock")
        val st = welcome.getJSONArray("state"); val ids = (0 until st.length()).map { st.getString(it) }
        // The commitments at a state after a redeal are Upkeep's (not yet ported): a first join only.
        if (ids.isNotEmpty()) refuse("unsupported", "a welcome at a state after a redeal")
        val C = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
        val sh = Codes.stateHash(ids)
        val servers = view.members.filter { it.kind == "server" }.map { it.key }.toSet()
        val shares = me.shares.associateWith { i ->
            val at = sigmas.filter { Json.isInt(it.opt("index")) && Json.long(it.get("index")) == i && it.optString("state") == sh }
            val fromInviter = at.firstOrNull { it.optString("from") == m } ?: refuse("sigma_missing", "the inviter's sigma")
            val fromServer = at.firstOrNull { it.optString("from") in servers } ?: refuse("sigma_missing", "a server's sigma")
            val share = Frost.repairShare(C, listOf(fromInviter.getString("sigma"), fromServer.getString("sigma")), i)
            if (mul(share) != derive(C, BigInteger.valueOf(i))) refuse("repair_failed", "share $i")
            share
        }
        return Joined(rec, recEv, changes, view, shares, C, ids)
    }
}
