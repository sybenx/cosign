// A co-signer's request handling (core §5.1–§5.8): the Kotlin counterpart of keykin/src/cosigner.ts,
// for the everyday one-call round, ECDH's sender rule and holds. Answers are JSON like the TS.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

class CoSigner(private val rec: JSONObject, changes: List<Event>, private val meKey: String, private val index: Long, private val share: BigInteger, private val now: () -> Long) {
    private val g = rec.getString("g"); private val epoch = rec.getJSONObject("epoch").getString("id")
    private val C: List<Pt?> = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
    private val view = Membership.compute(rec, changes)
    // Members from the computed membership only, never from the raw change list: a refused change
    // changes nothing here, and a change that isn't JSON can't break the constructor (review 8 H1).
    private val members: Map<String, Member> = view.members.associateBy { it.key }
    private val state = Codes.stateHash(emptyList())
    private val replay = HashMap<String, Pair<String, JSONObject?>>()
    private val holds = HashMap<String, Long>()

    private fun err(id: String, code: String) = JSONObject().put("v", 1).put("type", "error").put("re", id).put("code", code)

    fun handle(from: String, msg: JSONObject, sentAt: Long): JSONObject {
        val id = msg.optString("id")
        if (!Regex("^[0-9a-f]{32}$").matches(id) || !(Json.isInt(msg.opt("v")) && Json.long(msg.opt("v")) == 1L)) return err(id, "malformed")
        if (msg.optString("g") != g) return err(id, "wrong_group")
        if (msg.optString("epoch") != epoch) return err(id, "wrong_epoch")
        val type = msg.opt("type") as? String ?: return err(id, "unsupported")
        if (type !in setOf("sign", "commit", "ecdh", "hold")) return err(id, "unsupported")
        Rules.lifetime(type, msg.optString("cls"), now() - sentAt)?.let { return err(id, it) }
        val hash = hex(sha(utf8(Jcs.of(msg))))
        replay["$from:$id"]?.let { (h, a) -> return if (h == hash && a != null) a else err(id, "id_reused") }
        replay["$from:$id"] = hash to null
        val answer = try { when (type) { "sign" -> sign(from, msg); "commit" -> commit(from, msg); "ecdh" -> ecdh(from, msg); else -> hold(from, msg) } } catch (e: KeykinException) { err(id, e.code) }
        replay["$from:$id"] = hash to answer
        return answer
    }

    private fun sender(from: String): Member { if (from in view.removed) refuse("removed"); return members[from] ?: refuse("not_member") }

    private fun stale(msg: JSONObject) = if (msg.optString("state") != state) JSONObject().put("v", 1).put("type", "stale").put("re", msg.getString("id")).put("ids", JSONArray()) else null
    /** §5.7 item 2: every index of every participant, once, the sender and this co-signer among them,
     *  worth at least 4; a one-call round has exactly two participants. Returns the signers as sent. */
    private fun participants(msg: JSONObject, from: String, twoCall: Boolean): List<Long> {
        val arr = msg.optJSONArray("signers") ?: refuse("bad_signers")
        val sent = (0 until arr.length()).map { if (Json.isInt(arr.get(it))) Json.long(arr.get(it)) else refuse("bad_signers") }
        val owners = sent.map { i -> members.values.firstOrNull { i in it.shares } ?: refuse("bad_signers") }.distinctBy { it.key }
        if (owners.none { it.key == from } || owners.none { it.key == meKey }) refuse("bad_signers")
        if (!twoCall && owners.size != 2) refuse("bad_signers")
        if (owners.flatMap { it.shares }.sorted() != sent.sorted() || sent.size < 4) refuse("bad_signers")
        if (owners.any { it.key in view.removed }) refuse("removed")
        return sent
    }
    private fun commits(cs: JSONArray?, want: List<Long>): List<Frost.Committed> {
        if (cs == null) refuse("bad_commitments")
        val out = (0 until cs.length()).map { val c = cs.get(it) as? JSONObject ?: refuse("bad_commitments")
            Frost.Committed(if (Json.isInt(c.opt("i"))) Json.long(c.opt("i")) else refuse("bad_commitments"), "", c.optString("D"), c.optString("E")) }
        if (out.map { it.i }.sorted() != want.sorted()) refuse("bad_commitments")
        out.forEach { point(it.d); point(it.e) }
        return out
    }
    /** Two-call (§5.1) nonces: in memory only, for 120 s, used once (§5.2). Never in a snapshot. */
    private class Kept(val mine: Frost.Committed, val at: Long, var used: Boolean, val signers: List<Long>)
    private val twoCall = HashMap<String, Kept>()

    private fun commit(from: String, msg: JSONObject): JSONObject {
        val s = sender(from)
        stale(msg)?.let { return it }
        val signers = participants(msg, from, true)
        if (s.kind != "device" && s.kind != "helper") refuse("not_coordinator")
        // This port signs single events; a list's `count` is the TS reference's.
        if (msg.has("count") && !(Json.isInt(msg.opt("count")) && Json.long(msg.opt("count")) == 1L)) refuse("unsupported")
        if (msg.has("event")) wire(msg)
        twoCall.entries.removeIf { now() - it.value.at > 120 }
        val mine = Frost.commit(C, index, share, Frost.hedge(share, sha(utf8(Jcs.of(msg)), u32(0))))
        twoCall["$from:${msg.getString("id")}"] = Kept(mine, now(), false, signers)
        return JSONObject().put("v", 1).put("type", "commitments").put("re", msg.getString("id"))
            .put("commitments", JSONArray().put(JSONObject().put("i", index).put("D", mine.d).put("E", mine.e)))
    }

    private fun sign(from: String, msg: JSONObject): JSONObject {
        val s = sender(from)
        stale(msg)?.let { return it }
        val twoCall = msg.has("after")
        val signers = participants(msg, from, twoCall)
        if (s.kind != "device" && s.kind != "helper") refuse("not_coordinator")
        val kept: Kept?
        val all: List<Frost.Committed>
        if (!twoCall) {
            kept = null
            all = commits(msg.optJSONArray("commitments"), s.shares)
        } else {
            this.twoCall.entries.removeIf { now() - it.value.at > 120 }     // review 9 L3
            val k = this.twoCall["$from:${msg.opt("after")}"]
            if (k == null || now() - k.at > 120) refuse("unknown_after")
            if (k.used) refuse("after_used")
            k.used = true
            if (k.signers != signers) refuse("bad_signers")
            all = commits(msg.optJSONArray("commitments"), signers)
            val x = all.firstOrNull { it.i == index }
            if (x == null || x.d != k.mine.d || x.e != k.mine.e) refuse("bad_commitments")
            kept = k
        }
        // §5.7 items 4, 5, 7.
        val e = wire(msg)
        val kind = e.kind; val createdAt = e.createdAt; val tags = e.tags; val ev = msg.getJSONObject("event")
        if (!Rules.futureOk(kind, createdAt - now())) refuse("dated_ahead")
        if (kind == 30242) refuse("machinery")
        if (kind == 24302) { val c = try { Json.obj(ev.getString("content")) } catch (_: Exception) { refuse("not_a_change") }
            if ((c.optJSONArray("list")?.length() ?: 0) > 1) refuse("list_in_one_request"); refuse("unsupported_change") }
        val evId = e.id
        if (Rules.destructive(kind, ev.getString("content"), tags)) {
            val ap = msg.optJSONObject("approval")
            val pair = ap?.optJSONArray("pair")
            if (pair != null) {
                // Core 14.26 §5.8: a pair of two distinct current devices (the requester one of them) over "sign" ‖ event id.
                Approvals.checkSignPair(g, { k -> k in view.devices && k !in view.removed }, evId, pair, from)?.let { refuse(it) }
            } else {
                val l = ap?.optJSONObject("lock") ?: refuse("needs_approval")
                val lock = s.lock ?: refuse("needs_approval")
                if (l.getString("member") != from) refuse("needs_approval")
                checkAssertion(g, lock.getString("pub"), lock.getString("rp"), Codes.whatSign(evId), l.getJSONObject("assertion"))?.let { refuse(it) }
            }
        }
        // Fresh nonces for a one-call request, or the ones kept for `after`; either way used once (§5.2).
        val mine = kept?.mine ?: Frost.commit(C, index, share, Frost.hedge(share, sha(utf8(Jcs.of(msg)), u32(0))))
        val z = Frost.sign(C, mine, share, evId, if (kept != null) all else all + mine)
        // A used `after` is forgotten once it signed, as the TS reference does (review 9 L3, L5).
        if (kept != null) this.twoCall.remove("$from:${msg.opt("after")}")
        return JSONObject().put("v", 1).put("type", "partial").put("re", msg.getString("id"))
            .put("commitments", if (kept != null) JSONArray() else JSONArray().put(JSONObject().put("i", index).put("D", mine.d).put("E", mine.e))).put("z", JSONArray().put(JSONObject().put("i", index).put("z", z)))
    }
    /** §9.5: exactly the six fields, `id` included and recomputed. */
    private fun wire(msg: JSONObject): Event {
        val e = Event.shape(msg.opt("event") as? JSONObject ?: refuse("malformed", "event"), "cosign")
        if (e.pubkey != g) refuse("wrong_pubkey")
        if (eventId(e) != e.id) refuse("malformed", "the event id differs from its fields")
        return e
    }
    private fun ecdh(from: String, msg: JSONObject): JSONObject { if (sender(from).kind != "device") refuse("not_device"); refuse("unsupported") }
    private fun hold(from: String, msg: JSONObject): JSONObject {
        if (sender(from).kind != "device") refuse("not_device")
        val wait = Codes.holdWaitId(wire(msg).id)
        val end = holds.getOrPut(wait) { now() + Keykin.W }
        return JSONObject().put("v", 1).put("type", "notice").put("re", msg.getString("id")).put("kind", "hold").put("wait", wait).put("end", end)
    }
}
