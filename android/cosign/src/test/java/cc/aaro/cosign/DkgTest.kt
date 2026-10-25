package cc.aaro.cosign

import cc.aaro.cosign.core.Dkg
import cc.aaro.cosign.core.FrostNative
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.hexToBytes
import fr.acinq.secp256k1.Secp256k1
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/** A weighted key made by the phone (3 shares) and two servers (1 each), over a lossy "relay". */
class DkgTest {
    @Test fun phoneAndServersMakeOneKeyThatSigns() {
        val plan = mapOf("session" to "s1", "threshold" to 4L,
            "holders" to listOf(1L to "a", 2L to "b", 3L to "p", 4L to "p", 5L to "p").map { mapOf("idx" to it.first, "pk" to it.second) })
        // Through Json, as it would arrive.
        val parsed = Json.parse(Json.stringify(plan)) as Map<*, *>
        val queue = ArrayDeque<Triple<String, String, String>>() // from, to, message
        val rnd = Random(7)
        val runs = mutableMapOf<String, Dkg>()
        for (pk in listOf("a", "b", "p")) runs[pk] = Dkg(parsed, pk, { to, msg -> if (rnd.nextDouble() > 0.3) queue.add(Triple(pk, to, Json.stringify(msg))) }) {}
        repeat(30) {
            runs.values.forEach { it.tick() }
            while (queue.isNotEmpty()) { val (from, to, m) = queue.removeFirst(); runs[to]!!.take(Json.parse(m) as Map<*, *>, from) }
        }
        val done = runs.mapValues { it.value.done!! }
        val key = done["p"]!!.groupX
        assertTrue(done.values.all { it.groupX == key && it.members == done["p"]!!.members })
        assertEquals(listOf(3, 4, 5), done["p"]!!.shares.map { it.first })

        // The phone's 3 and server A's 1 sign.
        val group = Json.stringify(mapOf("groupX" to key, "threshold" to 4, "members" to done["p"]!!.members.map { mapOf("idx" to it.first, "sharePub" to it.second) }))
        val signers = done["p"]!!.shares + done["a"]!!.shares
        val msg = "%064x".format(42)
        val cs = signers.map { (i, s) -> Json.parse(FrostNative.commit(group, i, s)) as Map<*, *> }
        val commits = Json.stringify(cs.map { it["commit"] })
        val zs = signers.zip(cs).map { (sh, c) -> listOf(sh.first, FrostNative.sign(group, sh.first, sh.second, c["nonces"] as String, msg, commits)) }
        val sig = FrostNative.aggregate(group, msg, commits, Json.stringify(zs))
        assertTrue(Secp256k1.verifySchnorr(sig.hexToBytes(), msg.hexToBytes(), key.hexToBytes()))
    }
}
