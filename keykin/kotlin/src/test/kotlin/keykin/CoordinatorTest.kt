package keykin

import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The Kotlin coordinator against the Kotlin co-signer (itself checked against the TS reference's
 *  cosigner.json): a one-call round gives an event that verifies as BIP-340 under g. */
class CoordinatorTest {
    private val v = JSONObject(File(System.getProperty("keykin.cosigner")).readText())
    private val rec = JSONObject(Event.of(v.getJSONObject("record")).content)
    private val g = v.getString("g"); private val now = v.getLong("now")
    private val ctx = RoundContext(g, rec.getJSONObject("epoch").getString("id"), Codes.stateHash(emptyList()),
        (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) })
    private val dev = v.getJSONObject("device")
    private val shares = (0 until dev.getJSONArray("shares").length()).associate { dev.getJSONArray("shares").getJSONArray(it).let { p -> p.getLong(0) to BigInteger(p.getString(1), 16) } }
    private fun server(): CoSigner { val s = v.getJSONObject("server")
        return CoSigner(rec, (0 until v.getJSONArray("changes").length()).map { Event.of(v.getJSONArray("changes").getJSONObject(it)) }, s.getString("key"), s.getLong("index"), BigInteger(s.getString("share"), 16)) { now } }
    private val co = Signer(v.getJSONObject("server").getString("key"), listOf(4))

    @Test fun oneCallSigns() {
        val S = server()
        val r = OneCall(ctx, shares, co, Unsigned(g, now, 1, listOf(listOf("t", "kotlin")), "gm from the Kotlin coordinator"))
        val signed = r.finish(S.handle(dev.getString("key"), r.request, now))
        assertTrue(verifyEvent(Event.of(signed)))
        assertEquals(r.eventId, signed.getString("id"))
        assertEquals("used", assertFailsWith<KeykinException> { r.finish(JSONObject()) }.code, "nonces are used once")
    }

    @Test fun refusals() {
        val S = server()
        val r = OneCall(ctx, shares, co, Unsigned(g, now, 1, emptyList(), "x"))
        val p = S.handle(dev.getString("key"), r.request, now)
        val z0 = p.getJSONArray("z").getJSONObject(0)
        val bad = JSONObject(p.toString()); bad.getJSONArray("z").getJSONObject(0).put("z", scalarHex(BigInteger(z0.getString("z"), 16).add(BigInteger.ONE)))
        assertEquals("bad_partial", assertFailsWith<KeykinException> { r.finish(bad) }.code)
        val r2 = OneCall(ctx, shares, co, Unsigned(g, now, 1, emptyList(), "y"))
        assertEquals("needs_approval", assertFailsWith<KeykinException> { r2.finish(JSONObject().put("type", "error").put("code", "needs_approval")) }.code)
        assertEquals("wrong_pubkey", assertFailsWith<KeykinException> { OneCall(ctx, shares, co, Unsigned("ab".repeat(32), now, 1, emptyList(), "z")) }.code)
    }
}
