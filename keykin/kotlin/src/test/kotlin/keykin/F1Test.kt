package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** F1Watch (core §6.7.7, Server profile §4.1), as the TS reference's src/f1.ts. */
class F1Test {
    private val v = JSONObject(File(System.getProperty("keykin.f1")).readText())
    private val t0 = 1_800_000_000L

    @Test fun quietSevenDaysIsDead() {
        val w = F1Watch("ab".repeat(32))
        w.seat("h1", "k1", t0); w.seat("h2", "k2", t0)
        w.saw("h1", "serving", t0); w.saw("h2", "silent", t0)
        assertEquals(null, w.dead("h2", t0 + 6 * 86400))
        assertEquals("quiet", w.dead("h2", t0 + 7 * 86400))
        assertEquals(listOf("server:5"), w.card(listOf("server:4" to "h1", "server:5" to "h2"), t0 + 7 * 86400).map { it.getString("seat") }.filter { it == "server:5" })
    }
    @Test fun denialCountsOnlyWhileAPeerServes() {
        val w = F1Watch("ab".repeat(32))
        w.seat("h1", "k1", t0); w.seat("h2", "k2", t0)
        w.saw("h2", "denied", t0)
        w.saw("h1", "serving", t0 + 3600)
        assertEquals(null, w.dead("h2", t0 + 86400), "the peer hasn't served since the day passed")
        w.saw("h1", "serving", t0 + 86400 + 60)
        assertEquals("denied", w.dead("h2", t0 + 86400 + 60))
        w.saw("h2", "serving", t0 + 86400 + 120)
        assertEquals(null, w.dead("h2", t0 + 86400 + 120), "serving again clears it")
    }
    @Test fun tsSignedNotices() {
        val g = v.getString("g"); val host = v.getString("host"); val member = v.getString("member")
        val w = F1Watch(g); w.seat(host, member, t0)
        assertTrue(w.pushed(v.getJSONObject("pushed"), t0), "a TS-signed pushed notice prompts a notice_get")
        val forged = JSONObject(v.getJSONObject("pushed").toString()).put("seq", 9)
        assertFalse(w.pushed(forged, t0), "a changed notice doesn't verify")
        assertFalse(w.answer(v.getJSONObject("answer"), member, t0), "no request outstanding")
        w.asked(host, "cd".repeat(16), t0)
        assertFalse(w.answer(v.getJSONObject("answer"), "ff".repeat(32), t0), "only from the seat's member key")
        assertTrue(w.answer(v.getJSONObject("answer"), member, t0))
        assertEquals(1_900_000_000L, w.closing(host))
        // A closing date more than 30 days ahead isn't dead yet; within 30 days it is.
        val far = 1_900_000_000L - 31 * 86400; val near = 1_900_000_000L - 29 * 86400
        w.saw(host, "serving", far); assertEquals(null, w.dead(host, far))
        w.saw(host, "serving", near); assertEquals("shutdown", w.dead(host, near))
        // The cancel (a higher seq, no date) replaces it.
        w.asked(host, "cd".repeat(16), t0 + 10)
        assertTrue(w.answer(v.getJSONObject("cancel"), member, t0 + 10))
        assertEquals(null, w.closing(host))
        // It survives a dump and load.
        val w2 = F1Watch(g); w2.load(w.dump()); assertEquals(null, w2.closing(host)); assertEquals(null, w2.dead(host, t0 + 10))
    }
}
