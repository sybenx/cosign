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
        assertEquals("private-data", Grants.scopeForDecrypt(g, g, """[["p","x"]]"""), "list-shaped but unmatched (review 16 M2)")
        assertEquals("wallet", Grants.scopeForDecrypt(g, g, """[["privkey","x"]]"""))
        assertEquals("private-data", Grants.scopeForDecrypt(g, g, "a note"))
    }

    @Test fun aNip46SiteGetsOnlyItsScopes() {
        // The home's scope checks, without relays: a bound grant is a store entry; what it lacks is asked once.
        val d = device()
        val home = Nip46Home(d, RelayNet(emptyList()))
        val link = home.mintBunker(listOf("ws://127.0.0.1:1"), "coracle")
        val signer = java.net.URI(link).host; val secret = link.substringAfter("secret=")
        val client = "cd".repeat(32)
        fun call(method: String, vararg p: String) = home.answer(home.grants[signer]!!, client, method, p.toList())
        assertEquals("ack", call("connect", signer, secret).getString("result"))
        assertEquals(d.g, call("get_public_key").getString("result"))
        assertTrue(call("nip44_encrypt", "ef".repeat(32), "hi").getString("error").startsWith("permission: dms"))
        assertTrue(call("sign_event", JSONObject().put("kind", 3).put("content", "").put("tags", JSONArray()).toString()).getString("error").startsWith("permission: lists"))
        assertEquals(setOf("dms", "lists"), home.asks[signer]?.toSet())
        val e = d.grants.all().single { it.getString("door") == "nip46" }
        assertEquals(setOf("post", "sign-in"), d.grants.scopesOf(e))
        // Signed out elsewhere (here: ended in the store): the site is revoked.
        d.grants.end(d.pub, e.getString("id"))
        assertTrue(call("get_public_key").getString("error").startsWith("revoked:"))
    }

    @Test fun decryptScopesAsTsDecides() {
        val x = JSONObject(File(System.getProperty("keykin.decryptscopes")).readText())
        val ev = Evidence().also { it.load(x.getJSONObject("evidence")) }
        val cases = x.getJSONArray("cases")
        for (k in 0 until cases.length()) cases.getJSONObject(k).let { c ->
            assertEquals(c.getString("scope"), Grants.scopeForDecrypt(x.getString("g"), x.getString("g"), c.getString("plaintext"), c.getString("payload"), ev, c.getString("owner")), "case $k")
        }
    }
    @Test fun tokensAsTsJudges() {
        assertEquals(null, Grants.scopesForEvent(27235, listOf(listOf("u", "https://a.example/x"), listOf("method", "DELETE"))))
        assertEquals(listOf("sign-in", "host:b.example"), Grants.scopesForEvent(27235, listOf(listOf("u", "https://b.example/x"), listOf("method", "GET")), "a.example"))
        assertEquals(listOf("sign-in"), Grants.scopesForEvent(24242, listOf(listOf("t", "upload"), listOf("x", "ab".repeat(32)))))
        assertEquals(null, Grants.scopesForEvent(24242, listOf(listOf("t", "delete"))))
        assertEquals(listOf("post"), Grants.scopesForEvent(30023)); assertEquals(listOf("lists"), Grants.scopesForEvent(39089))
    }
}
