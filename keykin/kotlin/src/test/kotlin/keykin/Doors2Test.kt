package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

/** Doors §2 in Kotlin: the counted relays' health, as device/relays.ts; wildcards and delivered ends on a device
 *  restored from a TS snapshot (vectors/grants.json's). */
class Doors2Test {
    @Test fun relayHealthAsTs() {
        val h = RelayHealth(); val rec = listOf("a", "b", "c")
        for (k in 0 until 10) h.fetched(rec, listOf("a", "b"), rec, 1000L + k * 86400)
        assertEquals(listOf("a", "b"), h.counted(rec))
        assertEquals(listOf("a", "b"), h.toFetch(rec, 1000L + 10 * 86400))
        assertEquals(rec, h.toFetch(rec, 1000L + 17 * 86400))
        h.fetched(rec, rec, rec, 1000L + 17 * 86400); assertEquals(rec, h.counted(rec))
        val own = RelayHealth(); for (k in 0 until 20) own.fetched(rec, emptyList(), rec, k * 86400L); assertEquals(rec, own.counted(rec))
        // blocked:/restricted: over 12 hours makes it fetch-only, written to again weekly; passing refusals never count.
        val b = RelayHealth(); for (t in listOf(0L, 6 * 3600L, 13 * 3600L)) b.published(mapOf("c" to "blocked: no"), t)
        assertEquals(listOf("a", "b"), b.writable(rec, 14 * 3600L)); assertEquals(rec, b.counted(rec)); assertEquals(rec, b.writable(rec, 13 * 3600L + 7 * 86400))
        val w = RelayHealth(); for (r in listOf("publish timed out", "rate-limited: slow", "auth-required: x", "error: busy")) w.published(mapOf("c" to r), 0); assertEquals(rec, w.writable(rec, 1))
        // A relay that stays dead through 5-minute fetches is dropped after 7 days (review 19 H3).
        val dead = RelayHealth(); var t = 0L; while (t <= 8 * 86400) { dead.fetched(rec, listOf("a", "b"), rec, t); t += 300 }; assertEquals(listOf("a", "b"), dead.counted(rec))
        assertTrue(RelayHealth.majority(listOf("a", "b"), rec)); assertFalse(RelayHealth.majority(listOf("a"), rec)); assertFalse(RelayHealth.majority(emptyList(), emptyList()))
        val back = RelayHealth(); back.load(b.dump()); assertEquals(listOf("a", "b"), back.writable(rec, 14 * 3600L))
    }

    @Test fun wildcardsAndDeliveredEnds() {
        val v = JSONObject(File(System.getProperty("keykin.grants")).readText())
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val gone = java.util.concurrent.CopyOnWriteArrayList<String>(); d.onEnds { gone += it }
        val a = d.grants.make("https://a.example", "a", "nip55", "pkg@1", listOf("sign-in"))
        val b = d.grants.make("https://b.example", "b", "nip55", "pkg@1", listOf("sign-in"))
        // An end naming one grant, then a wildcard for every grant made before a time.
        assertEquals(listOf(a.getString("id")), d.grants.takeEnds(listOf(JSONObject().put("by", d.pub).put("id", a.getString("id")).put("at", 1))))
        assertEquals(listOf(b.getString("id")), d.grants.takeEnds(listOf(JSONObject().put("by", d.pub).put("id", "*").put("at", 1).put("before", System.currentTimeMillis() / 1000 - 115))))
        assertTrue(d.grants.own.isEmpty())
        // Another device's ends never touch this one's grants.
        val c = d.grants.make("https://c.example", "c", "nip55", "pkg@1", listOf("sign-in"))
        assertEquals(emptyList(), d.grants.takeEnds(listOf(JSONObject().put("by", "ab".repeat(32)).put("id", "*").put("at", 1).put("before", Long.MAX_VALUE / 2))))
        assertTrue(d.grants.own.containsKey(c.getString("id")))
        // A wildcard for another home is a tombstone listing uses.
        val t = d.grants.endAll("cd".repeat(32), 100)!!
        assertEquals("*", t.getString("id")); assertEquals(100L, t.getLong("before"))
    }

    @Test fun nip46HomeSurvivesARestart() {
        val v = JSONObject(File(System.getProperty("keykin.grants")).readText())
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        Keykin.wire = JdkWire
        val link = d.nip46.mintBunker(listOf("ws://127.0.0.1:1"), "coracle", listOf("sign-in", "post"))
        val signer = java.net.URI(link).host
        val again = Device.fromSnapshot(d.snapshot(), RelayNet(emptyList()))
        val g = again.nip46.grants[signer]!!
        assertEquals(hex(d.nip46.grants[signer]!!.signerSk), hex(g.signerSk), "the signer key comes back")
        assertEquals(listOf("ws://127.0.0.1:1"), g.relays); assertEquals("coracle", g.site)
    }
}
