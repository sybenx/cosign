package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** vectors/metadata.json, made by the TS reference: a Kotlin device judges a decrypt on another device's synced
 *  records, as TS does; and the TS reference reads what Kotlin publishes (vectors/check-metadata.ts). */
class MetadataTest {
    private val v = JSONObject(File(System.getProperty("keykin.metadata")).readText())
    private fun device() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
    @Test fun judgesOnAnotherDevicesRecords() {
        val d = device()
        fun judge() = Grants.scopeForDecrypt(d.g, d.g, v.getString("plaintext"), v.getString("ciphertext"), d.evidence, "x:y")
        assertEquals(v.getString("without"), judge())
        d.meta.take(v.getJSONArray("events").let { a -> (0 until a.length()).map { Event.of(a.getJSONObject(it)) } })
        assertEquals(v.getString("with"), judge())
    }
    @Test fun tsReadsWhatKotlinPublishes() {
        val d = device()
        d.meta.encrypted(Nip44.encrypt("a kotlin list", ByteArray(32) { 7 }), "member")
        // Built by the same code that publishes, signed here by a stand-in account key the check script trusts as g.
        val acct = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = 1 }
        val evs = d.meta.unsignedForTest(Secp.Reference.pub(acct)).map { u -> Envelope().sign(acct, u.kind, u.createdAt, u.tags, u.content) }
        val input = JSONObject().put("g", Secp.Reference.pub(acct)).put("maker", d.pub).put("base_dk", v.getString("base_dk")).put("data_key", JSONObject().put("state", d.dataKey().first).put("key", hex(d.dataKey().second))).put("events", JSONArray(evs))
        val f = File.createTempFile("meta", ".json").also { it.writeText(input.toString()); it.deleteOnExit() }
        val root = File(System.getProperty("keykin.metadata")).parentFile.parentFile
        val p = ProcessBuilder("node", File(root, "vectors/check-metadata.ts").path, f.path).directory(root).redirectErrorStream(true).start()
        val out = JSONObject(p.inputStream.bufferedReader().readText().trim().lines().last()); p.waitFor()
        assertEquals(1, out.getInt("owners"), out.toString())
    }
}
