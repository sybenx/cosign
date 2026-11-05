package keykin

import org.json.JSONArray
import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals

/** Doors 20 §2 in Kotlin: the vault plaintexts no site gets, judged as TS judges them (test/doors20.test.ts CASES). */
class Doors20Test {
    private val g = "ab".repeat(32)
    @Test fun vaultPlaintextsAsTs() {
        val rumor = { kind: Int, content: String -> JSONObject().put("kind", kind).put("pubkey", g).put("content", content).put("tags", JSONArray()).put("created_at", 1).toString() }
        val cases = listOf(
            rumor(4812, "hi") to true,
            JSONObject().put("vault", "v1").put("keys", JSONArray()).toString() to true,
            JSONObject().put("vault", "v1").put("secret", "x").toString() to true,
            JSONObject().put("vault", "v1").put("genesis", JSONObject()).toString() to true,
            rumor(14, JSONObject().put("vault", "v").put("inboxes", JSONArray()).toString()) to true,
            JSONObject().put("vault", "v1").put("name", "Family").toString() to false,
            rumor(14, "a message") to false,
            "a private note" to false,
            JSONArray(listOf(JSONArray(listOf("p", "x")))).toString() to false)
        for ((t, want) in cases) assertEquals(want, Doors.vaultPlaintext(t), t)
    }
}
