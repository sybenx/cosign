package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** vectors/policy.json, made by the TS reference: Device policy §2's verdict on each case, judged here as TS judged it. */
class PolicyTest {
    private val v = JSONObject(File(System.getProperty("keykin.policy")).readText())
    private fun strs(a: JSONArray) = (0 until a.length()).map { a.getString(it) }
    private fun tags(a: JSONArray) = (0 until a.length()).map { strs(a.getJSONArray(it)) }

    @Test fun judgesAsTs() {
        val g = v.getString("g"); val now = v.getLong("now"); val ck = unhex(v.getString("ck"))
        val cases = v.getJSONArray("cases")
        val wrong = ArrayList<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val h = History { g }
            c.getJSONArray("history").let { a -> for (k in 0 until a.length()) h.take(Event.of(a.getJSONObject(k))) }
            val led = Ledger(); led.take(c.getJSONObject("ledger")) { true }
            val lookup = c.getJSONArray("lookup").let { a -> (0 until a.length()).map { Event.of(a.getJSONObject(it)) } }
            val e = c.getJSONObject("event")
            val ev = Unsigned(e.getString("pubkey"), e.getLong("created_at"), e.getInt("kind"), tags(e.getJSONArray("tags")), e.getString("content"))
            val got = Policy.judge(ev, Policy.Ctx(g, now, c.getString("owner"), strs(c.getJSONArray("scopes")), h, led,
                { x -> try { Nip44.decrypt(x, ck) } catch (_: Exception) { null } }, { _, _ -> lookup }))
            if (got.level != c.getString("level") || got.row != c.getString("row")) wrong += "${c.getString("name")}: ${got.level}/${got.row}, TS ${c.getString("level")}/${c.getString("row")}"
        }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test fun normalisesUrlsAsTs() {
        val u = v.getJSONArray("urls")
        for (i in 0 until u.length()) u.getJSONArray(i).let { assertEquals(it.getString(1), Policy.normValue(it.getString(0))) }
    }

    @Test fun recordsRoundTrip() {
        val l = Ledger()
        l.sign("aa".repeat(32), "dev1:g"); l.log("removed", "dev1:g", "3", listOf("pub p x"), 5); l.del(Del(5, "dev1:g", 2, false, false, false))
        l.setPresite("dev1:g", "3", "bb".repeat(32)); l.approve("dev1:g", "3", "cc".repeat(32), 5)
        val back = Ledger(); back.take(Json.obj(l.data().toString())) { true }
        assertEquals(Jcs.of(l.data()), Jcs.of(back.data()))
        val none = Ledger(); none.take(l.data()) { it == "member" }
        assertEquals(0, none.size())
    }
}
