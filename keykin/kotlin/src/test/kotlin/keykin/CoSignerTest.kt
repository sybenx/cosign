package keykin

import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class CoSignerTest {
    @Test fun steps() {
        val v = JSONObject(File(System.getProperty("keykin.cosigner")).readText())
        val rec = JSONObject(Event.of(v.getJSONObject("record")).content)
        val changes = (0 until v.getJSONArray("changes").length()).map { Event.of(v.getJSONArray("changes").getJSONObject(it)) }
        val srv = v.getJSONObject("server")
        val S = CoSigner(rec, changes, srv.getString("key"), srv.getLong("index"), BigInteger(srv.getString("share"), 16)) { v.getLong("now") }
        val steps = v.getJSONArray("steps")
        for (k in 0 until steps.length()) {
            val s = steps.getJSONObject(k)
            val a = S.handle(s.getString("from"), s.getJSONObject("request"), s.getLong("sent_at"))
            assertEquals(s.getString("expect"), if (a.getString("type") == "error") a.getString("code") else a.getString("type"), s.getString("name"))
            if (a.getString("type") == "partial") {
                // Kotlin's partial must verify against P_4 over the TS coordinator's commitments plus its own.
                val req = s.getJSONObject("request"); val ev = req.getJSONObject("event")
                val tags = ev.getJSONArray("tags").let { t -> (0 until t.length()).map { x -> val q = t.getJSONArray(x); (0 until q.length()).map { q.getString(it) } } }
                val evId = eventId(Event("", ev.getString("pubkey"), ev.getLong("created_at"), ev.getInt("kind"), tags, ev.getString("content"), ""))
                val C = (0 until rec.getJSONArray("commitment").length()).map { point(rec.getJSONArray("commitment").getString(it)) }
                val cs = req.getJSONArray("commitments").let { c -> (0 until c.length()).map { val o = c.getJSONObject(it); Frost.Committed(o.getLong("i"), "", o.getString("D"), o.getString("E")) } }
                val mine = a.getJSONArray("commitments").getJSONObject(0).let { Frost.Committed(it.getLong("i"), "", it.getString("D"), it.getString("E")) }
                kotlin.test.assertTrue(Frost.verifyShare(C, evId, cs + mine, 4, a.getJSONArray("z").getJSONObject(0).getString("z")), "${s.getString("name")}: partial verifies")
            }
        }
    }
}
