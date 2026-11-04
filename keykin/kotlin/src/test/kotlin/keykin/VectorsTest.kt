// docs/keykin/vectors/vectors.json, the same computed cases the TypeScript passes (core §14).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VectorsTest {
    private val v = JSONObject(File(System.getProperty("keykin.vectors")).readText()).getJSONObject("cases")
    private fun ints(a: JSONArray) = (0 until a.length()).map { a.getLong(it) }
    private fun strs(a: JSONArray) = (0 until a.length()).map { a.getString(it) }

    @Test fun joinCheck() { val a = v.getJSONArray("join_check"); for (k in 0 until a.length()) { val c = a.getJSONObject(k); assertEquals(c.getString("code"), Codes.joinCheck(c.getString("g"), c.getString("m"), c.getString("n"), c.getString("s"), c.getString("t"))) } }
    @Test fun listHashAndPair() {
        val l = v.getJSONArray("list_hash")
        assertEquals(l.getJSONObject(0).getString("jcs"), Jcs.of(l.getJSONObject(0).getJSONArray("list")))
        for (k in 0 until l.length()) assertEquals(l.getJSONObject(k).getString("sha256"), Codes.listHash(Jcs.of(l.getJSONObject(k).getJSONArray("list"))))
        val p = v.getJSONObject("pair_code"); assertEquals(p.getString("code"), Codes.pairCode(p.getString("g"), p.getString("list_hash"), p.getString("r")))
    }
    @Test fun indices() { val c = v.getJSONObject("indices"); val i = Codes.deviceIndices(c.getString("g"), c.getString("epoch_id"), c.getString("key"), c.getLong("salt")); assertEquals(ints(c.getJSONArray("indices")), i); assertEquals(strs(c.getJSONArray("identifiers_32byte")), i.map { scalarHex(BigInteger.valueOf(it)) }) }
    @Test fun waitIds() { val c = v.getJSONObject("wait_ids"); assertEquals(c.getString("hold"), Codes.holdWaitId(c.getString("event_id"))); assertEquals(c.getString("recovery"), Codes.recoveryWaitId(c.getString("backup_key"), c.getString("epoch_id"), c.getString("r"))) }
    @Test fun lockChallenge() {
        val g = v.getJSONArray("join_check").getJSONObject(0).getString("g"); val ev = v.getJSONObject("wait_ids").getString("event_id")
        val lh = v.getJSONArray("list_hash").getJSONObject(0).getString("sha256"); val a = v.getJSONArray("lock_challenge")
        assertEquals(a.getJSONObject(0).getString("challenge"), Codes.lockChallenge(g, Codes.whatSign(ev)))
        assertEquals(a.getJSONObject(1).getString("challenge"), Codes.lockChallenge(g, Codes.whatChange(lh, v.getJSONObject("indices").getString("epoch_id"), a.getJSONObject(1).getLong("expiry"))))
        assertEquals(a.getJSONObject(2).getString("challenge"), Codes.lockChallenge(g, Codes.whatCancel(v.getJSONObject("wait_ids").getString("recovery"))))
    }
    @Test fun waitedDigest() { val c = v.getJSONObject("waited_statement_digest"); assertEquals(c.getString("digest"), Codes.waitedDigest(v.getJSONArray("join_check").getJSONObject(0).getString("g"), c.getString("kind"), c.getString("wait"), c.getLong("start"), c.getLong("end"))) }
    @Test fun commitmentRebuild() {
        val c = v.getJSONObject("commitment_rebuild"); val C = strs(c.getJSONArray("commitment")).map(::point)
        val pts = listOf(BigInteger.ZERO to C[0]) + ints(c.getJSONArray("device_indices")).mapIndexed { k, i -> BigInteger.valueOf(i) to point(c.getJSONArray("device_points").getString(k)) }
        val r = rebuild(pts)
        assertEquals(strs(c.getJSONArray("rebuilt")), r.map { comp(it!!) })
        assertFalse(r == strs(c.getJSONObject("negative").getJSONArray("commitment")).map(::point))
        val d = c.getJSONObject("derived_points"); for (k in d.keySet()) assertEquals(d.getString(k), comp(derive(C, BigInteger(k))!!))
    }
    @Test fun ecdhDleq() {
        val c = v.getJSONObject("ecdh_dleq"); val C = strs(v.getJSONObject("commitment_rebuild").getJSONArray("commitment")).map(::point)
        assertEquals(c.getString("state"), Codes.stateHash(strs(c.getJSONArray("state_ids"))))
        val args = { z: String -> verifyDleq(c.getString("g"), c.getString("epoch_id"), c.getString("state"), ints(c.getJSONArray("signers")), C, c.getString("Q"), c.getLong("i"), c.getString("Y"), c.getString("R1"), c.getString("R2"), z) }
        assertTrue(args(c.getString("z"))); assertFalse(args(c.getJSONArray("negative").getJSONObject(0).getString("z")))
    }
    @Test fun futureDates() { val a = v.getJSONArray("future_dates"); for (k in 0 until a.length()) { val c = a.getJSONObject(k); assertEquals(c.getBoolean("accept"), Rules.futureOk(c.getInt("kind"), c.getLong("ahead_s")), c.toString()) } }
    @Test fun statelessDestructive() {
        val a = v.getJSONArray("stateless_destructive")
        for (k in 0 until a.length()) {
            val c = a.getJSONObject(k); val e = c.getJSONObject("event")
            val tags = if (e.has("tags")) (0 until e.getJSONArray("tags").length()).map { strs(e.getJSONArray("tags").getJSONArray(it)) } else List(e.optInt("targets", 0)) { listOf("e", "%064x".format(it)) }
            val needs = if (Rules.destructive(e.getInt("kind"), e.optString("content", ""), tags, e.optInt("unapproved_targets_last_10min", 0))) "approval or hold" else "nothing"
            assertEquals(c.getString("needs"), needs, c.toString())
        }
    }
    @Test fun lifetimes() { val a = v.getJSONArray("lifetimes"); for (k in 0 until a.length()) { val c = a.getJSONObject(k); assertEquals(c.getBoolean("accept"), Rules.lifetime(c.getString("type"), c.getString("cls"), c.optLong("age_s", 0)) == null, c.toString()) } }
    @Test fun helperSeat() { val c = v.getJSONObject("helper_seat"); assertEquals(ints(c.getJSONArray("indices")), Codes.helperSeat(c.getString("g"))) }
    @Test fun redealApply() {
        val c = v.getJSONObject("redeal_apply"); val C = strs(v.getJSONObject("commitment_rebuild").getJSONArray("commitment")).map(::point); val D = strs(c.getJSONArray("D")).map(::point)
        val cs = listOf(C[0]) + D.mapIndexed { k, d -> add(C[k + 1], d) }
        assertEquals(strs(c.getJSONArray("C_S")), cs.map { comp(it!!) })
        val dd = listOf<Pt?>(null) + D
        assertEquals(c.getString("delta_i_G"), comp(derive(dd, BigInteger.valueOf(c.getLong("device_index")))!!))
        assertEquals(c.getString("new_P_i"), comp(derive(cs, BigInteger.valueOf(c.getLong("device_index")))!!))
        val pr = c.getJSONObject("paper_reissue"); ints(pr.getJSONArray("b")).forEachIndexed { k, b -> assertEquals(pr.getJSONArray("delta_b_G").getString(k), comp(derive(dd, BigInteger.valueOf(b))!!)) }
    }
    @Test fun dataKey() { val c = v.getJSONObject("data_key"); assertEquals(c.getString("dk_S"), Codes.dataKey(c.getString("base"), strs(c.getJSONArray("seeds_sorted")).reversed())) }
    @Test fun signpost() {
        val c = v.getJSONObject("signpost")
        assertEquals(c.getString("d"), Codes.signpostD(c.getString("backup_key")))
        assertEquals(c.getString("h"), Codes.signpostH(c.getString("epoch_id"), Jcs.of(c.getJSONArray("servers"))))
        assertEquals(c.getString("device_copy_key"), Codes.signpostDeviceKey(v.getJSONObject("data_key").getString("base")))
    }
    @Test fun seatedDigest() { val c = v.getJSONObject("seated_reply_digest"); assertEquals(c.getString("digest"), Codes.seatedDigest(c.getString("H_key"), unhex(c.getString("challenge")), sha(utf8("sealed-reply-ciphertext")))) }
}
