package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The Kotlin dealer's parts, checked with the Kotlin device's own checks (the TS side checks them over
 *  relays in test/kotlin.dealer.e2e.test.ts). */
class DealerTest {
    private val v = JSONObject(File(System.getProperty("keykin.upkeep")).readText())
    private fun fresh() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))

    @Test fun aSoftLockAssertionChecks() {
        val lock = SoftLock("keykin.test", ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = 1 })
        val g = "ab".repeat(32); val w = utf8("change") + ByteArray(56)
        assertNull(checkAssertion(g, lock.pub.getString("pub"), lock.pub.getString("rp"), w, lock.assert(g, w)))
        assertEquals("lock_challenge", checkAssertion(g, lock.pub.getString("pub"), lock.pub.getString("rp"), w + byteArrayOf(1), lock.assert(g, w)))
    }

    @Test fun xchachaSealsWhatItOpens() {
        val key = ByteArray(32) { it.toByte() }
        for (n in listOf(0, 1, 15, 16, 17, 64, 1000)) {
            val plain = ByteArray(n) { (it * 7).toByte() }
            val box = XChaCha.seal(key, ByteArray(24) { (it + 3).toByte() }, plain)
            assertTrue(XChaCha.open(key, box).contentEquals(plain))
            val bad = box.copyOf().also { it[30.coerceAtMost(it.size - 1)] = (it[30.coerceAtMost(it.size - 1)].toInt() xor 1).toByte() }
            assertTrue(runCatching { XChaCha.open(key, bad) }.isFailure)
        }
    }

    @Test fun aDealtRedealAppliesAndItsPaperItemVerifies() {
        val d = fresh()
        val backupSeat = (0 until d.rec.getJSONObject("seats").getJSONArray("backup").length()).map { d.rec.getJSONObject("seats").getJSONArray("backup").getLong(it) }
        val post = Deal.postListView(d.view, JSONArray().put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub))))
        assertTrue(d.view.backup !in post.keys && d.pub in post.keys)
        val dl = Deal.deal(d.g, d.sk, d.ids, post.mapValues { it.value.shares }, d.view.backup!!, backupSeat)
        val r = dl.redeal
        assertTrue(schnorrVerify(r.getString("sig"), Approvals.detached("redeal", d.g, Json.obj(Jcs.of(JSONObject(r.toString()).also { it.remove("sig") }))), d.pub))
        val applied = Upkeep.apply(d.g, d.state, r, dl.deltas[d.pub]!!, backupSeat, emptySet())
        assertEquals(d.ids + r.getString("id"), applied.state.ids)
        assertTrue(Upkeep.verifyPaperItem(r, dl.paperItem, dl.releaseSeed, dl.paperCk, backupSeat))
        // Every other recipient's deltas are on D too.
        for ((k, ds) in dl.deltas) for ((i, x) in ds) assertEquals(mul(x), Upkeep.deriveDelta(Upkeep.dPoints(r), java.math.BigInteger.valueOf(i)), "$k $i")
    }
}
