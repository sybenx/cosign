package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Review 13's Kotlin findings, each as a regression test, on vectors/upkeep.json. */
class Review13Test {
    private val v = JSONObject(File(System.getProperty("keykin.upkeep")).readText())
    private val step0 = v.getJSONArray("steps").getJSONObject(0)
    private fun events(a: JSONArray) = (0 until a.length()).map { Event.of(a.getJSONObject(it)) }
    private fun fresh() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
    private fun key() = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
    private val env = Envelope()
    private fun realBody(d: Device) = env.unwrap(d.sk, step0.getJSONArray("deliveries").getJSONObject(0)).body

    @Test fun h1JunkChangesNeverJoin() {
        val d = fresh(); val n = d.changes.size
        val junk = (0 until 300).map { k -> Event.of(env.sign(key(), 24302, 1, listOf(listOf("v", "1"), listOf("epoch", d.epochId)),
            JSONObject().put("v", 1).put("g", d.g).put("epoch", d.epochId).put("change", JSONObject().put("remove", "ab".repeat(32))).put("n", k).toString())) }
        val t0 = System.currentTimeMillis()
        d.takeChanges(junk)
        assertEquals(n, d.changes.size)
        assertTrue(System.currentTimeMillis() - t0 < 5000, "and cheap")
    }

    @Test fun m1PendingOnlyFromCurrentDevicesBounded() {
        val d = fresh(); val stranger = key()
        repeat(100) { assertEquals("junk", d.takeDelivery(env.wrap(stranger, d.pub, JSONObject().put("type", "delta").put("redeal", hex(key().copyOf(16))).put("deltas", JSONArray()), 1))) }
        val dealer = unhex(v.getString("dealer_sk"))
        assertEquals("junk", d.takeDelivery(env.wrap(dealer, d.pub, JSONObject().put("type", "delta").put("redeal", "x:" + hex(key().copyOf(16))).put("deltas", JSONArray()), 1)))
        repeat(16) { assertEquals("kept", d.takeDelivery(env.wrap(dealer, d.pub, JSONObject().put("type", "delta").put("redeal", hex(key().copyOf(16))).put("deltas", JSONArray()), 1))) }
        assertEquals("full", d.takeDelivery(env.wrap(dealer, d.pub, JSONObject().put("type", "delta").put("redeal", hex(key().copyOf(16))).put("deltas", JSONArray()), 1)))
        // A device that isn't flooded applies the dealer's delivery that came before its change.
        val e = fresh()
        e.takeDelivery(step0.getJSONArray("deliveries").getJSONObject(0)); e.takeChanges(events(step0.getJSONArray("changes")))
        assertEquals(step0.getJSONObject("after").getString("state"), e.ctx.state)
    }

    @Test fun m2AMalformedDealerFieldDropsTheDelivery() {
        val dealer = unhex(v.getString("dealer_sk"))
        for (bad in listOf<(JSONObject) -> Unit>({ it.put("release", 5) }, { it.put("dk", JSONObject.NULL) }, { it.put("deltas", JSONArray().put(JSONArray().put(1).put("zz"))) },
                { it.put("deltas", JSONArray().put(JSONArray().put(1).put("ff".repeat(32)))) })) {
            val d = fresh(); val b = realBody(d); bad(b)
            d.takeDelivery(env.wrap(dealer, d.pub, b, 1))
            d.takeChanges(events(step0.getJSONArray("changes")))
            d.applyAll()   // never throws, and the bad one is gone
            assertTrue(d.notices.any { it.optString("kind") == "bad_delivery" }, b.toString())
            assertTrue(d.ids.isEmpty())
            // The real delivery still applies afterwards.
            d.takeDelivery(step0.getJSONArray("deliveries").getJSONObject(0)); d.applyAll()
            assertEquals(step0.getJSONObject("after").getString("state"), d.ctx.state)
        }
    }

    @Test fun aPaperItemThatIsNoItemIsShownAndItsValuesKept() {
        val dealer = unhex(v.getString("dealer_sk"))
        val d = fresh(); val b = realBody(d).put("paper_item", "x")
        d.takeDelivery(env.wrap(dealer, d.pub, b, 1)); d.takeChanges(events(step0.getJSONArray("changes")))
        assertEquals(step0.getJSONObject("after").getString("state"), d.ctx.state, "applied, as TS does")
        assertTrue(d.notices.any { it.optString("kind") == "bad_paper_item" })
        assertEquals(d.ids, d.keptRedeals)
    }

    @Test fun m5TheStateSurvivesARestart() {
        var saved = ""
        val d = fresh(); d.persist = { saved = it }
        d.takeDelivery(step0.getJSONArray("deliveries").getJSONObject(0)); d.takeChanges(events(step0.getJSONArray("changes")))
        val back = Device.fromSnapshot(saved, RelayNet(emptyList()))
        assertEquals(d.ctx.state, back.ctx.state)
        assertEquals(hex(d.dataKey().second), hex(back.dataKey().second))
        assertEquals(d.members.removed(0), back.members.removed(0))
        assertEquals(hex(d.dataKeyFor(Codes.stateHash(emptyList()))!!), hex(back.dataKeyFor(Codes.stateHash(emptyList()))!!), "older keys too")
        // TS's own fields it carried (backup material) come back as they were.
        assertEquals(JSONObject(v.getString("before")).opt("base").toString(), JSONObject(saved).opt("base").toString())
    }

    @Test fun m6AWipeEndsTheHomeAndSticks() {
        var saved = ""
        val d = fresh(); d.persist = { saved = it }
        val home = Nip46Home(d, RelayNet(emptyList()))
        home.mintBunker(listOf("ws://127.0.0.1:1"))
        var gone = 0; d.onGone { gone++ }
        d.wipe()
        assertEquals(1, gone); assertTrue(home.grants.isEmpty())
        assertFailsWith<KeykinException> { d.dataKey() }
        assertFailsWith<KeykinException> { Device.fromSnapshot(saved, RelayNet(emptyList())) }
        assertFalse(home.handle(JSONObject()))
    }

    @Test fun l1ScalarsAndSeedsAsTsReadsThem() {
        assertFailsWith<KeykinException> { Upkeep.scalar("ff".repeat(32)) }
        assertFailsWith<KeykinException> { Upkeep.scalar("-1") }
        assertFailsWith<KeykinException> { XChaCha.open(ByteArray(64), ByteArray(48)) }
    }
}
