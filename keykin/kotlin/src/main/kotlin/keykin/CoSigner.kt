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
    private val members: Map<String, Member> = run {
        val recM = (0 until rec.getJSONArray("members").length()).map { member(rec.getJSONArray("members").getJSONObject(it)) }
        val m = HashMap<String, Member>()
        recM.filter { it.key !in view.removed }.forEach { m[it.key] = it }
        for (e in changes) { val c = JSONObject(e.content).getJSONObject("change"); c.optJSONObject("add")?.let { a -> val k = a.getString("key")
            if (k in view.devices) m[k] = Member(k, "device", Codes.deviceIndices(g, epoch, k, a.getLong("salt")), a.optJSONObject("lock"), null, null, a) } }
        m
    }
    private val state = Codes.stateHash(emptyList())
    private val replay = HashMap<String, Pair<String, JSONObject?>>()
    private val holds = HashMap<String, Long>()

    private fun err(id: String, code: String) = JSONObject().put("v", 1).put("type", "error").put("re", id).put("code", code)

    fun handle(from: String, msg: JSONObject, sentAt: Long): JSONObject {
        val id = msg.optString("id")
        if (!Regex("^[0-9a-f]{32}$").matches(id) || msg.opt("v") != 1) return err(id, "malformed")
        if (msg.optString("g") != g) return err(id, "wrong_group")
        if (msg.optString("epoch") != epoch) return err(id, "wrong_epoch")
        val type = msg.opt("type") as? String ?: return err(id, "unsupported")
        if (type !in setOf("sign", "ecdh", "hold")) return err(id, "unsupported")
        Rules.lifetime(type, msg.optString("cls"), now() - sentAt)?.let { return err(id, it) }
        val hash = hex(sha(utf8(Jcs.of(msg))))
        replay["$from:$id"]?.let { (h, a) -> return if (h == hash && a != null) a else err(id, "id_reused") }
        replay["$from:$id"] = hash to null
        val answer = try { when (type) { "sign" -> sign(from, msg); "ecdh" -> ecdh(from, msg); else -> hold(from, msg) } } catch (e: KeykinException) { err(id, e.code) }
        replay["$from:$id"] = hash to answer
        return answer
    }

    private fun sender(from: String): Member { if (from in view.removed) refuse("removed"); return members[from] ?: refuse("not_member") }

    private fun sign(from: String, msg: JSONObject): JSONObject {
        val s = sender(from)
        if (msg.optString("state") != state) return JSONObject().put("v", 1).put("type", "stale").put("re", msg.getString("id")).put("ids", JSONArray())
        // §5.7 item 2: exactly the two participants' indices.
        val signers = (0 until msg.getJSONArray("signers").length()).map { msg.getJSONArray("signers").getLong(it) }.sorted()
        val owners = signers.map { i -> members.values.firstOrNull { i in it.shares } ?: refuse("bad_signers") }.map { it.key }.toSet()
        if (from !in owners || meKey !in owners || owners.size != 2) refuse("bad_signers")
        if (signers != (s.shares + index).sorted()) refuse("bad_signers")
        if (s.kind != "device" && s.kind != "helper") refuse("not_coordinator")
        val cs = msg.getJSONArray("commitments")
        if ((0 until cs.length()).map { cs.getJSONObject(it).getLong("i") }.sorted() != s.shares.sorted()) refuse("bad_commitments")
        (0 until cs.length()).forEach { point(cs.getJSONObject(it).getString("D")); point(cs.getJSONObject(it).getString("E")) }
        // §5.7 items 4, 5, 7.
        val ev = msg.getJSONObject("event")
        if (ev.optString("pubkey") != g) refuse("wrong_pubkey")
        val kind = ev.getInt("kind"); val createdAt = ev.getLong("created_at")
        val tags = ev.getJSONArray("tags").let { t -> (0 until t.length()).map { k -> val a = t.getJSONArray(k); (0 until a.length()).map { a.getString(it) } } }
        if (!Rules.futureOk(kind, createdAt - now())) refuse("dated_ahead")
        if (kind == 30242) refuse("machinery")
        if (kind == 24302) { val c = try { JSONObject(ev.getString("content")) } catch (_: Exception) { refuse("not_a_change") }
            if ((c.optJSONArray("list")?.length() ?: 0) > 1) refuse("list_in_one_request"); refuse("unsupported_change") }
        val evId = eventId(Event("", g, createdAt, kind, tags, ev.getString("content"), ""))
        if (Rules.destructive(kind, ev.getString("content"), tags)) {
            val l = msg.optJSONObject("approval")?.optJSONObject("lock") ?: refuse("needs_approval")
            val lock = s.lock ?: refuse("needs_approval")
            if (l.getString("member") != from) refuse("needs_approval")
            checkAssertion(g, lock.getString("pub"), lock.getString("rp"), Codes.whatSign(evId), l.getJSONObject("assertion"))?.let { refuse(it) }
        }
        // Fresh nonces for this request, used once (§5.2).
        val theirs = (0 until cs.length()).map { val c = cs.getJSONObject(it); Frost.Committed(c.getLong("i"), "", c.getString("D"), c.getString("E")) }
        val mine = Frost.commit(C, index, share, Frost.hedge(share, sha(utf8(Jcs.of(msg)), u32(0))))
        val z = Frost.sign(C, mine, share, evId, theirs + mine)
        return JSONObject().put("v", 1).put("type", "partial").put("re", msg.getString("id"))
            .put("commitments", JSONArray().put(JSONObject().put("i", index).put("D", mine.d).put("E", mine.e))).put("z", JSONArray().put(JSONObject().put("i", index).put("z", z)))
    }
    private fun ecdh(from: String, msg: JSONObject): JSONObject { if (sender(from).kind != "device") refuse("not_device"); refuse("unsupported") }
    private fun hold(from: String, msg: JSONObject): JSONObject {
        if (sender(from).kind != "device") refuse("not_device")
        val ev = msg.getJSONObject("event"); if (ev.optString("pubkey") != g) refuse("wrong_pubkey")
        val wait = Codes.holdWaitId(eventId(Event.of(ev.put("id", "").put("sig", ""))))
        val end = holds.getOrPut(wait) { now() + 3 * 86400 }
        return JSONObject().put("v", 1).put("type", "notice").put("re", msg.getString("id")).put("kind", "hold").put("wait", wait).put("end", end)
    }
}
