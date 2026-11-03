package keykin

import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Core §9.5, the JSON profile (the differential probes in vectors/diff hold many more cases). */
class JsonTest {
    private fun bad(t: String) = assertFailsWith<KeykinException>(t) { Json.parse(t) }.also { assertEquals("malformed", it.code) }
    @Test fun reader() {
        for (t in listOf("\ufeff[]", "[1,]", "{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "[1.0]", "[1e0]", "[-0]", "[9007199254740992]", "[01]",
            "[\"\\ud800\"]", "[\"\\u000b\"]", "[\"\t\"]", "[" .repeat(33) + "]".repeat(33), "", "[] []")) bad(t)
        assertEquals(9007199254740991L, (Json.parse("[9007199254740991]") as org.json.JSONArray).get(0))
        assertEquals("[\"\\b\\t\\n\\f\\r\"]", Jcs.of(Json.parse("[\"\\b\\t\\n\\f\\r\"]")))
        assertEquals("{\"1\":3,\"10\":1,\"9\":2}", Jcs.of(Json.parse("{\"10\":1,\"9\":2,\"1\":3}")))
        assertEquals("[\"a/b\u2028\u007f\"]", Jcs.of(Json.parse("[\"a\\/b\u2028\u007f\"]")))
        assertTrue(Json.parse("{\"n\":1e999,\"m\":-0}", grammar = true) is JSONObject)
    }
    @Test fun writersRefuseWhatTheReaderRefuses() {
        assertFailsWith<KeykinException> { Json.str("a\u000bb") }
        assertFailsWith<KeykinException> { Json.str("\ud800") }
    }
    @Test fun utf8AndBase64() {
        for (b in listOf(byteArrayOf(0xc0.toByte(), 0xaf.toByte()), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()))) assertFailsWith<KeykinException> { Json.utf8Strict(b) }
        assertEquals("\ufeff{}", Json.utf8Strict(byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte(), '{'.code.toByte(), '}'.code.toByte())))
        for (s in listOf("AB", "A", "AA==", "_-")) assertFailsWith<KeykinException>(s) { b64d(s) }
        for (s in listOf("AB==", "AA", "A===")) assertFailsWith<KeykinException>(s) { b64std(s) }
        assertEquals(1, b64d("AA").size); assertEquals(1, b64std("AA==").size)
    }
    @Test fun eventShapeAndRules() {
        val o = JSONObject().put("id", "0".repeat(64)).put("pubkey", "ab".repeat(32)).put("created_at", 1L).put("kind", 1L).put("tags", org.json.JSONArray()).put("content", "x")
        Event.shape(o, "rumor")
        assertFailsWith<KeykinException> { Event.shape(JSONObject(o.toString()).put("relays", 1L), "rumor") }
        assertFailsWith<KeykinException> { Event.shape(JSONObject(o.toString()).put("kind", 65536L), "rumor") }
        assertTrue(Rules.destructive(3, "", listOf(listOf("p"))))
        assertEquals(false, Rules.destructive(3, "", listOf(listOf("p", ""))))
        assertEquals(1, Rules.deletionTargets(List(6) { listOf("e", "x") }))
        assertTrue(Rules.destructive(10002, "", listOf(listOf("r", "WSS://x"))))
        assertEquals(false, Rules.destructive(0, "{\"name\":\"x\",\"n\":1e999}", emptyList()))
    }
    @Test fun paperPlaceholderKeepsModuleFields() {
        val c = Json.obj("{\"paper\":{\"key\":\"k\",\"replaces\":\"r\",\"inner\":\"i\",\"state\":[],\"holders\":[\"h\"],\"x\":{\"y\":1}}}")
        assertEquals("[{\"paper\":{\"holders\":[\"h\"],\"key\":\"k\",\"replaces\":\"r\",\"x\":{\"y\":1}}}]", Jcs.of(Approvals.placeholder(org.json.JSONArray().put(c))))
        assertEquals(Approvals.key(Json.obj("{\"add\":{\"key\":\"k\",\"salt\":1}}")), Approvals.key(Json.obj("{\"add\":{\"key\":\"k\",\"salt\":1,\"lock\":null}}")))
    }
}
