package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** vectors/upkeep.json, made by the TS reference: a device's snapshot, then a redeal and a remove with its
 *  redeal as they reached it. The Kotlin device must hold what TS held after each: the same state, shares,
 *  data key and members log, with the paper item verified. */
class UpkeepTest {
    private val v = JSONObject(File(System.getProperty("keykin.upkeep")).readText())
    private fun events(a: JSONArray) = (0 until a.length()).map { Event.of(a.getJSONObject(it)) }

    @Test fun appliesWhatTsApplied() {
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        assertEquals(v.getString("device"), d.pub)
        val heard = ArrayList<Members.Event>()
        d.members.onRemoved { heard += it }
        val steps = v.getJSONArray("steps")
        for (k in 0 until steps.length()) {
            val s = steps.getJSONObject(k); val after = s.getJSONObject("after")
            // The stranger's copy of the first delivery arrives first: it never stands in for the dealer's.
            if (k == 0) d.takeDelivery(v.getJSONObject("stranger_delivery"))
            val dl = s.getJSONArray("deliveries"); for (i in 0 until dl.length()) d.takeDelivery(dl.getJSONObject(i))
            // And after the dealer's, still before the redeal is known.
            if (k == 0) d.takeDelivery(v.getJSONObject("stranger_delivery"))
            d.takeChanges(events(s.getJSONArray("changes")))
            assertEquals(after.getJSONArray("ids").toList(), d.ids.sorted(), "step $k ids")
            assertEquals(after.getString("state"), d.ctx.state, "step $k state")
            val sh = after.getJSONArray("shares")
            assertEquals((0 until sh.length()).associate { sh.getJSONArray(it).let { p -> p.getLong(0) to p.getString(1) } }, d.shares.mapValues { scalarHex(it.value) }, "step $k shares")
            val (st, key) = d.dataKey()
            assertEquals(after.getString("data_key_state"), st); assertEquals(after.getString("data_key"), hex(key), "step $k data key")
            val dev = after.getJSONObject("devices"); val (self, asOf, keys) = d.members.devices()
            assertEquals(dev.getString("self"), self); assertEquals(dev.getString("asOf"), asOf)
            val ks = dev.getJSONArray("keys")
            assertEquals((0 until ks.length()).map { ks.getJSONObject(it).let { x -> Triple(x.getString("key"), if (x.isNull("added_by")) null else x.getString("added_by"), x.getBoolean("flagged")) } },
                keys.map { Triple(it.key, it.addedBy, it.flagged) }, "step $k devices")
            val rm = after.getJSONArray("removed")
            assertEquals((0 until rm.length()).map { rm.getJSONObject(it).let { x -> listOf(x.get("seq").toString(), x.getString("key"), x.getString("why"), x.optString("change"), x.optString("state")) } },
                d.members.removed(0).map { listOf(it.seq.toString(), it.key, it.why, it.change ?: "", it.state ?: "") }, "step $k removed")
            assertTrue(d.notices.none { it.optString("kind") == "bad_paper_item" || it.optString("kind") == "bad_delivery" }, d.notices.toString())
        }
        // The data under the first state is still readable; the removal was told twice (logged, then its state).
        val first = steps.getJSONObject(0).getJSONObject("after")
        assertEquals(first.getString("data_key"), hex(d.dataKeyFor(first.getString("data_key_state"))!!))
        assertEquals(2, heard.count { it is Members.Event.Entry })
        assertTrue(d.kept.isEmpty(), "every paper item verified, so no paper values kept")
    }

    @Test fun xchachaOpensWhatTsSealed() {
        // The paper item of the first delivery opens under its release seed and conversation key.
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val body = Envelope().unwrap(d.sk, v.getJSONArray("steps").getJSONObject(0).getJSONArray("deliveries").getJSONObject(0)).body
        val opened = Upkeep.openItem(body.getJSONObject("paper_item"), body.getString("release"), body.getString("paper_ck"))
        assertEquals(body.getString("redeal"), opened.getString("redeal"))
    }
}
