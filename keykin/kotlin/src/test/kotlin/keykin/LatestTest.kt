package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** `Device.latest`: the app's own process reads the account's public replaceable events from this device's history, and
 *  asks the relays only when its last ask is older than it allows. */
class LatestTest {
    private val v = JSONObject(File(System.getProperty("keykin.grants")).readText())
    private fun device() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
    private fun signed(d: Device, kind: Int, tags: List<List<String>>, at: Long, content: String = ""): Event {
        val u = Unsigned(d.g, at, kind, tags, content); return Event(u.id, d.g, at, kind, tags, content, "00".repeat(64))
    }

    @Test fun cachedThenAskedOnlyWhenOld() {
        val d = device()
        d.guard.signed(signed(d, 0, emptyList(), d.now - 100, "{\"name\":\"a\"}"), "member")
        var asks = 0
        val relays: (String) -> Triple<List<Event>, Int, Int> = { asks++; Triple(emptyList(), 1, 1) }
        // The cache alone: no ask.
        val x = d.latest(0, null, -1, relays)
        assertEquals("{\"name\":\"a\"}", x.getJSONObject("event").getString("content")); assertEquals(0, asks); assertEquals(0L, x.getLong("checked_at"))
        // Never asked: ask once, then the answer is fresh for an hour.
        d.latest(0, null, 3600, relays); d.latest(0, null, 3600, relays)
        assertEquals(1, asks)
        assertEquals(d.now, d.latest(0, null, 3600, relays).getLong("checked_at"))
        // Kind 3 has nothing: null, not an error.
        assertTrue(d.latest(3, null, -1, relays).isNull("event"))
    }

    @Test fun onlyTheAccountsVerifiedEventsAtThatAddress() {
        val d = device()
        val forged = signed(d, 10002, listOf(listOf("r", "wss://evil")), d.now)   // a zero signature from a relay
        val other = Keykin.secp.let { val sk = ByteArray(32).also { it[31] = 7 }; Event("00".repeat(32), it.pub(sk), d.now, 10002, emptyList(), "", "00".repeat(64)) }
        val r = d.latest(10002, null, 0) { Triple(listOf(forged, other), 2, 2) }
        assertTrue(r.isNull("event"))
        // A relay that answers nothing useful still counts as asked; none answering leaves it unasked.
        assertEquals(d.now, r.getLong("checked_at"))
        assertEquals(0L, d.latest(10000, null, 0) { Triple(emptyList(), 0, 2) }.getLong("checked_at"))
    }

    @Test fun publicReplaceableKindsOnly() {
        val d = device()
        assertEquals("not_replaceable", assertFailsWith<KeykinException> { d.latest(1, null, -1) }.code)
        assertEquals("not_replaceable", assertFailsWith<KeykinException> { d.latest(4, null, -1) }.code)
        assertEquals("malformed", assertFailsWith<KeykinException> { d.latest(30023, null, -1) }.code)
        assertTrue(d.latest(30023, "post", -1).isNull("event"))
    }
}
