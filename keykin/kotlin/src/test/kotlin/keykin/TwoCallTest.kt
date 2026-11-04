package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Core §5.1–§5.2 two-call co-signing in the Kotlin co-signer: `commit`, then `sign` with `after`. The
 *  test drives the round as the device would, with the fixture device's shares from cosigner.json. */
class TwoCallTest {
    private val v = JSONObject(File(System.getProperty("keykin.cosigner")).readText())
    private val rec = JSONObject(Event.of(v.getJSONObject("record")).content)
    private val g = v.getString("g"); private val epoch = rec.getJSONObject("epoch").getString("id"); private val now = v.getLong("now")
    private val C = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
    private val dev = v.getJSONObject("device"); private val devKey = dev.getString("key")
    private val devShares = (0 until dev.getJSONArray("shares").length()).map { dev.getJSONArray("shares").getJSONArray(it).let { p -> p.getLong(0) to BigInteger(p.getString(1), 16) } }
    private fun server(): CoSigner { val s = v.getJSONObject("server")
        return CoSigner(rec, (0 until v.getJSONArray("changes").length()).map { Event.of(v.getJSONArray("changes").getJSONObject(it)) }, s.getString("key"), s.getLong("index"), BigInteger(s.getString("share"), 16)) { now } }
    private fun id() = hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })
    private fun base(type: String) = JSONObject().put("v", 1).put("type", type).put("g", g).put("epoch", epoch).put("id", id()).put("cls", "sign")
        .put("state", Codes.stateHash(emptyList())).put("signers", JSONArray(listOf(1, 2, 3, 4)))
    private fun event(content: String): Pair<JSONObject, String> {
        val e = Event("", g, now, 1, emptyList(), content, ""); val id = eventId(e)
        return JSONObject().put("pubkey", g).put("created_at", now).put("kind", 1).put("tags", JSONArray()).put("content", content).put("id", id) to id
    }
    private fun cj(cs: List<Frost.Committed>) = JSONArray(cs.map { JSONObject().put("i", it.i).put("D", it.d).put("E", it.e) })

    @Test fun commitThenSign() {
        val S = server()
        val commit = base("commit")
        val c = S.handle(devKey, commit, now)
        assertEquals("commitments", c.getString("type"))
        val theirs = c.getJSONArray("commitments").getJSONObject(0).let { Frost.Committed(it.getLong("i"), "", it.getString("D"), it.getString("E")) }
        val mine = devShares.map { (i, s) -> Frost.commit(C, i, s, Frost.hedge(s, utf8("test"))) }
        val (ev, evId) = event("two-call from Kotlin")
        val sign = base("sign").put("after", commit.getString("id")).put("event", ev).put("commitments", cj(mine + theirs))
        val a = S.handle(devKey, sign, now)
        assertEquals("partial", a.getString("type"), a.optString("code"))
        assertTrue(Frost.verifyShare(C, evId, mine + theirs, 4, a.getJSONArray("z").getJSONObject(0).getString("z")), "the partial verifies over the round's commitments")
        // The kept nonces are used once: a second sign after the same commit is refused.
        assertEquals("after_used", S.handle(devKey, base("sign").put("after", commit.getString("id")).put("event", event("again").first).put("commitments", cj(mine + theirs)), now).getString("code"))
    }

    @Test fun refusals() {
        val S = server()
        val (ev, _) = event("x")
        val mine = devShares.map { (i, s) -> Frost.commit(C, i, s, Frost.hedge(s, utf8("t"))) }
        fun after(c: JSONObject) = base("sign").put("after", c.getString("id")).put("event", ev)
        val c1 = base("commit"); S.handle(devKey, c1, now)
        val wrong = Frost.Committed(4, "", mine[0].d, mine[0].e)
        assertEquals("bad_commitments", S.handle(devKey, after(c1).put("commitments", cj(mine + wrong)), now).getString("code"), "not the commitments this server returned")
        val c2 = base("commit"); S.handle(devKey, c2, now)
        assertEquals("bad_signers", S.handle(devKey, after(c2).put("signers", JSONArray(listOf(4, 3, 2, 1))).put("commitments", cj(mine)), now).getString("code"), "signers differ from the commit")
        assertEquals("unknown_after", S.handle(devKey, after(base("commit")).put("commitments", cj(mine)), now).getString("code"), "never committed")
        assertEquals("unsupported", S.handle(devKey, base("commit").put("count", 2), now).getString("code"), "lists are the TS reference's")
        assertEquals("bad_signers", S.handle(devKey, base("commit").put("signers", JSONArray(listOf(1, 2, 4))), now).getString("code"), "worth less than 4, or missing an index")
    }
}
