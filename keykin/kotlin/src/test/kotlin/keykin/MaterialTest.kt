package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** A paper's material (core §4.3, §7.2, 14.21 §4.5): Kotlin opens what TS made (vectors/material.json), and the TS
 *  reference opens what Kotlin makes (vectors/check-material.ts). */
class MaterialTest {
    private val v = JSONObject(File(System.getProperty("keykin.material")).readText())
    private val Ksk = unhex(v.getString("K_sk"))
    private fun records() = v.getJSONArray("records").let { a -> (0 until a.length()).map { a.getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } } }

    @Test fun opensTsMaterial() {
        val base = v.getJSONObject("base"); val seeds = v.getJSONArray("seeds").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
        assertEquals(v.getString("inner"), Material.inner(base, seeds))
        val b = Upkeep.openItem(base, v.getString("base_seed"), backupSk = Ksk)
        assertEquals(v.getString("base_dk"), b.getString("dk"))
        val dkOf = v.getJSONObject("dk_of").let { o -> o.keys().asSequence().associateWith { o.getString(it) } }
        // Only the seeds whose sha matches a co-signed redeal's dk (the vector names two of three).
        assertEquals(dkOf.keys, Material.openSeeds(seeds, v.getString("paper_seed"), Ksk, dkOf).keys)
        assertEquals(emptyMap(), Material.openSeeds(seeds, "00".repeat(32), Ksk, dkOf), "the wrong release seed opens nothing")
    }

    @Test fun tsOpensKotlinMaterial() {
        val shares = mapOf(5L to BigInteger("1234", 16), 6L to BigInteger("abcdef", 16))
        val base = Material.baseItem(Ksk, v.getString("base_seed"), shares, v.getString("base_dk"), listOf("00".repeat(16)))
        val seeds = Material.seedItems(Ksk, v.getString("paper_seed"), records())
        val input = JSONObject().put("K_sk", v.getString("K_sk")).put("base_seed", v.getString("base_seed")).put("paper_seed", v.getString("paper_seed"))
            .put("base", base).put("seeds", JSONArray(seeds)).put("inner", Material.inner(base, seeds)).put("records", JSONArray(records().map { JSONArray(listOf(it.first, it.second)) }))
        val f = File.createTempFile("material", ".json").also { it.writeText(input.toString()); it.deleteOnExit() }
        val root = File(System.getProperty("keykin.material")).parentFile.parentFile
        val p = ProcessBuilder("node", File(root, "vectors/check-material.ts").path, f.path).directory(root).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText().trim(); p.waitFor()
        val r = try { JSONObject(out.lines().last()) } catch (e: Exception) { error("TS said: $out") }
        assertTrue(r.getBoolean("ok"), out)
        assertEquals(v.getString("base_dk"), r.getJSONObject("base").getString("dk"))
    }

    @Test fun packAndChunk() {
        val many = (1..1001).map { k -> k.toString().padStart(32, '0') to "ab".repeat(32) }
        val items = Material.seedItems(Ksk, v.getString("paper_seed"), many)
        assertEquals(2, items.size, "at most 1,000 records per item")
        assertEquals(many.take(1000).sortedBy { it.first }, Material.unpackSeeds(Material.packSeeds(many.take(1000).reversed())))
    }
}
