package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** A paper opened at a recovery (core §6.5 step 4): Kotlin opens what the TS reference opened, to the same shares, data
 *  key and seeds (vectors/open-material.json, from a simulated account with two redeals). */
class OpenMaterialTest {
    private val v = JSONObject(File(System.getProperty("keykin.openmaterial")).readText())
    private val i = v.getJSONObject("input")
    private fun objs(a: JSONArray) = (0 until a.length()).map { a.getJSONObject(it) }
    private fun open(base: JSONObject = i.getJSONObject("base"), items: List<JSONObject> = objs(i.getJSONArray("items")), state: Set<String> = (0 until i.getJSONArray("state").length()).map { i.getJSONArray("state").getString(it) }.toSet()) =
        Material.openMaterial(i.getString("g"), unhex(i.getString("K_sk")), i.getString("pin"), base, i.getString("base_seed"), items,
            i.getJSONArray("seeds").let { a -> (0 until a.length()).associate { a.getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } } },
            objs(i.getJSONArray("seed_items")), i.getJSONArray("C0").let { a -> (0 until a.length()).map { point(a.getString(it)) } }, objs(i.getJSONArray("redeals")), state)

    @Test fun opensAsTsDid() {
        val o = open(); val out = v.getJSONObject("out")
        assertEquals(out.getJSONArray("shares").let { a -> (0 until a.length()).associate { a.getJSONArray(it).let { p -> Json.long(p.get(0)) to p.getString(1) } } },
            o.shares.mapValues { scalarHex(it.value) })
        assertEquals(out.getString("dk"), o.dk)
        assertEquals((0 until out.getJSONArray("dk_seed_hashes").length()).map { out.getJSONArray("dk_seed_hashes").getString(it) }, o.dkSeeds.map { hex(sha(unhex(it))) }.sorted())
    }
    @Test fun refusesWhatDoesntAddUp() {
        // A paper item missing for a redeal of the state; a base that isn't the pinned one; a state with a redeal it can't open.
        assertEquals("missing_item", assertFailsWith<KeykinException> { open(items = emptyList()) }.code)
        val forged = JSONObject(i.getJSONObject("base").toString()).put("box", "00".repeat(64))
        assertEquals("bad_material", assertFailsWith<KeykinException> { open(base = forged) }.code)
    }
}
