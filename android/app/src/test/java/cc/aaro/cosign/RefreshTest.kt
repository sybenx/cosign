package cc.aaro.cosign

import cc.aaro.cosign.core.Dkg
import cc.aaro.cosign.core.FrostNative
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.Refresh
import cc.aaro.cosign.core.SystemEnv
import cc.aaro.cosign.core.hexToBytes
import fr.acinq.secp256k1.Secp256k1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A weighted key (phone 1–3, tablet 4–6, servers 7 and 8) refreshed without the tablet: same key, new shares, the tablet's stop working. */
class RefreshTest {
    private fun makeKey(): Map<String, Dkg.Result> {
        val holders = listOf(1 to "p", 2 to "p", 3 to "p", 4 to "t", 5 to "t", 6 to "t", 7 to "a", 8 to "b")
        val plan = Json.parse(Json.stringify(mapOf("session" to "s", "threshold" to 4, "holders" to holders.map { mapOf("idx" to it.first, "pk" to it.second) }))) as Map<*, *>
        val q = ArrayDeque<Triple<String, String, String>>()
        val runs = listOf("p", "t", "a", "b").associateWith { pk -> Dkg(plan, pk, { to, m -> q.add(Triple(pk, to, Json.stringify(m))) }) {} }
        repeat(10) { runs.values.forEach { it.tick() }; while (q.isNotEmpty()) { val (f, t, m) = q.removeFirst(); runs[t]!!.take(Json.parse(m) as Map<*, *>, f) } }
        return runs.mapValues { it.value.done!! }
    }

    private fun signs(groupX: String, points: List<Pair<Int, String>>, shares: List<Pair<Int, String>>): Boolean = try {
        val group = Json.stringify(mapOf("groupX" to groupX, "threshold" to 4, "members" to points.map { mapOf("idx" to it.first, "sharePub" to it.second) }))
        val msg = "%064x".format(7)
        val cs = shares.map { (i, s) -> Json.parse(FrostNative.commit(group, i, s)) as Map<*, *> }
        val commits = Json.stringify(cs.map { it["commit"] })
        val zs = shares.zip(cs).map { (sh, c) -> listOf(sh.first, FrostNative.sign(group, sh.first, sh.second, c["nonces"] as String, msg, commits)) }
        Secp256k1.verifySchnorr(FrostNative.aggregate(group, msg, commits, Json.stringify(zs)).hexToBytes(), msg.hexToBytes(), groupX.hexToBytes())
    } catch (_: Exception) { false }

    @Test fun refreshWithoutTheLostTablet() {
        val key = makeKey()
        val groupX = key["p"]!!.groupX
        val oldPoints = key["p"]!!.members
        val left = oldPoints.filter { it.first !in 4..6 }
        val owner = mapOf(1 to "p", 2 to "p", 3 to "p", 7 to "a", 8 to "b")
        val plan = Json.parse(Json.stringify(mapOf("epoch" to 1, "threshold" to 4, "dealers" to listOf("p", "a"),
            "holders" to left.map { mapOf("idx" to it.first, "pk" to owner[it.first]) }, "points" to left.map { listOf(it.first, it.second) }))) as Map<*, *>
        val q = ArrayDeque<Triple<String, String, String>>()
        val out = HashMap<String, Refresh.Result>()
        val runs = listOf("p", "a", "b").associateWith { pk -> Refresh(plan, pk, key[pk]!!.shares, { to, m -> q.add(Triple(pk, to, Json.stringify(m))) }, { out[pk] = it }, SystemEnv) }
        repeat(3) { runs.values.forEach { it.tick() }; while (q.isNotEmpty()) { val (f, t, m) = q.removeFirst(); runs[t]!!.take(Json.parse(m) as Map<*, *>, f) } }
        assertEquals(3, out.size)
        val newPoints = out["p"]!!.points
        assertEquals(newPoints, out["b"]!!.points)
        assertTrue("phone + server A, new epoch", signs(groupX, newPoints, out["p"]!!.shares + out["a"]!!.shares))
        assertTrue("phone + server B, new epoch", signs(groupX, newPoints, out["p"]!!.shares + out["b"]!!.shares))
        val mixed = newPoints + oldPoints.filter { it.first in 4..6 }
        assertTrue("signing still works with the removed tablet's old points still listed", signs(groupX, mixed, out["p"]!!.shares + out["a"]!!.shares))
        assertFalse("the lost tablet's old shares + a new server share", signs(groupX, mixed, key["t"]!!.shares + out["a"]!!.shares))
    }
}
