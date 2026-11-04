package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** §6.7.6: a Kotlin re-issued paper item, checked by the TS reference (vectors/check-reissue.ts) as a server
 *  checks it, and opened with the paper's key. */
class ReissueTest {
    private val v = JSONObject(File(System.getProperty("keykin.upkeep")).readText())
    private val step0 = v.getJSONArray("steps").getJSONObject(0)
    @Test fun aKotlinReissueIsWhatTsAccepts() {
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val env = Envelope()
        // The dealer's paper item doesn't verify here, so the device keeps δ(b) for the redeal.
        val b = env.unwrap(d.sk, step0.getJSONArray("deliveries").getJSONObject(0)).body.put("paper_item", "x")
        d.takeDelivery(env.wrap(unhex(v.getString("dealer_sk")), d.pub, b, 1))
        d.takeChanges((0 until step0.getJSONArray("changes").length()).map { Event.of(step0.getJSONArray("changes").getJSONObject(it)) })
        val id = d.ids.single()
        val item = d.reissueItemFor(id)!!
        val seat = d.rec.getJSONObject("seats").getJSONArray("backup")
        val input = JSONObject().put("g", d.g).put("redeal", d.view.redeals[id]!!.r).put("item", item).put("K", d.view.backup).put("devices", JSONArray(d.memberKeys()))
            .put("backup_seat", seat).put("release", b.getString("release")).put("paper_sk", v.getString("paper_sk"))
        val f = File.createTempFile("reissue", ".json").also { it.writeText(input.toString()); it.deleteOnExit() }
        val root = File(System.getProperty("keykin.upkeep")).parentFile.parentFile
        val p = ProcessBuilder("node", File(root, "vectors/check-reissue.ts").path, f.path).directory(root).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText().trim().lines().last()
        p.waitFor()
        val r = JSONObject(out)
        assertEquals(JSONObject.NULL, r.opt("check"), out)
        assertEquals(true, r.getBoolean("opens"), out)
    }
}
