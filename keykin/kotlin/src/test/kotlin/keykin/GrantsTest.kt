package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** vectors/grants.json, made by the TS reference: a Kotlin device reads another device's grant event and lists
 *  what TS lists; and what Kotlin publishes, the TS reference reads (vectors/check-grants.ts). */
class GrantsTest {
    private val v = JSONObject(File(System.getProperty("keykin.grants")).readText())
    private fun device() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
    private fun events() = v.getJSONArray("events").let { a -> (0 until a.length()).map { Event.of(a.getJSONObject(it)) } }

    @Test fun readsWhatTsPublished() {
        val d = device()
        d.grants.take(events())
        val got = d.grants.all().map { Triple(it.getString("says"), it.getJSONArray("scopes").let { s -> (0 until s.length()).map { s.getString(it) } }, it.getString("by")) }.sortedBy { it.first }
        val want = v.getJSONArray("listed").let { a -> (0 until a.length()).map { a.getJSONObject(it).let { x -> Triple(x.getString("says"), x.getJSONArray("scopes").let { s -> (0 until s.length()).map { s.getString(it) } }, x.getString("by")) } } }
        assertEquals(want, got)
        // A tampered event (another member's set under the maker's d) is not read.
        val e0 = v.getJSONArray("events").getJSONObject(0)
        assertEquals(null, Grants.read(d.g, d.pub, v.getString("base_dk"), { d.dataKeyFor(it) }, listOf(Event.of(e0))), "not B's own d")
    }

    @Test fun tsReadsWhatKotlinPublishes() {
        val d = device()
        d.grants.make("https://kotlin.example", "kotlin-site", "nip55", "pkg@1", listOf("sign-in", "post"))
        val (state, key) = d.dataKey()
        val unsigned = Grants.events(d.g, d.sk, v.getString("base_dk"), state, key, d.grants.set(), 1_900_000_000)
        // The account signs it in a real device; here a stand-in event with a valid shape is what readMaker checks,
        // so the TS side reads the unsigned parts by a test key acting as the account.
        val acct = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = 1 }
        val g = Secp.Reference.pub(acct)
        val env = Envelope()
        val unsignedForG = Grants.events(g, d.sk, v.getString("base_dk"), state, key, JSONObject(Jcs.of(d.grants.set())).also { s ->
            s.put("entries", JSONArray((0 until s.getJSONArray("entries").length()).map { Grants.signEntry(g, d.sk, s.getJSONArray("entries").getJSONObject(it).also { e -> e.remove("by_sig"); e.remove("by") }) })) }, 1_900_000_000)
        val evs = unsignedForG.map { u -> env.sign(acct, u.kind, u.createdAt, u.tags, u.content) }
        val input = JSONObject().put("g", g).put("maker", d.pub).put("base_dk", v.getString("base_dk")).put("data_key", JSONObject().put("state", state).put("key", hex(key))).put("events", JSONArray(evs))
        val f = File.createTempFile("grants", ".json").also { it.writeText(input.toString()); it.deleteOnExit() }
        val root = File(System.getProperty("keykin.grants")).parentFile.parentFile
        val p = ProcessBuilder("node", File(root, "vectors/check-grants.ts").path, f.path).directory(root).redirectErrorStream(true).start()
        val out = JSONObject(p.inputStream.bufferedReader().readText().trim().lines().last()); p.waitFor()
        val set = out.optJSONObject("set") ?: error("TS read nothing: $out")
        assertEquals("kotlin-site", set.getJSONArray("entries").getJSONObject(0).getString("says"))
        assertTrue(out.getBoolean("signed"), "the entry's by_sig verifies in TS")
        assertEquals(1, unsigned.size)
    }

    @Test fun scopesAsTsSees() {
        assertEquals("lists", Grants.scopeForEvent(3)); assertEquals("wallet", Grants.scopeForEvent(17375)); assertEquals("sign-in", Grants.scopeForEvent(22242)); assertEquals("post", Grants.scopeForEvent(1))
        val g = "ab".repeat(32)
        assertEquals("dms", Grants.scopeForDecrypt(g, "cd".repeat(32), null))
        assertEquals("lists", Grants.scopeForDecrypt(g, g, """[["p","x"]]"""))
        assertEquals("wallet", Grants.scopeForDecrypt(g, g, """[["privkey","x"]]"""))
        assertEquals("private-data", Grants.scopeForDecrypt(g, g, "a note"))
    }
}
