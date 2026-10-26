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

/**
 * The quiet refresh's check round (COSIGN.md §7.7), on a real key: before anything is
 * committed, the phone signs one message with each server on the *pending* shares, and only a
 * real signature by the key lets it commit. A swap leaves a gone server out of that epoch, and
 * what it holds then combines with nothing.
 *
 * A weighted key: phone 1–3, servers 7, 8 and 9, threshold 4.
 */
class QuietRefreshTest {
    private val holders = listOf(1 to "p", 2 to "p", 3 to "p", 7 to "a", 8 to "b", 9 to "c")

    private fun makeKey(): Map<String, Dkg.Result> {
        val plan = Json.parse(Json.stringify(mapOf("session" to "s", "threshold" to 4,
            "holders" to holders.map { mapOf("idx" to it.first, "pk" to it.second) }))) as Map<*, *>
        val q = ArrayDeque<Triple<String, String, String>>()
        val runs = listOf("p", "a", "b", "c").associateWith { pk -> Dkg(plan, pk, { to, m -> q.add(Triple(pk, to, Json.stringify(m))) }) {} }
        repeat(10) { runs.values.forEach { it.tick() }; while (q.isNotEmpty()) { val (f, t, m) = q.removeFirst(); runs[t]!!.take(Json.parse(m) as Map<*, *>, f) } }
        return runs.mapValues { it.value.done!! }
    }

    private fun members(points: List<Pair<Int, String>>) = listOf(
        Member(1, "Phone", "phone", "p", points.first { it.first == 1 }.second,
            listOf(1, 2, 3).map { i -> Point(i, points.first { it.first == i }.second) }),
    ) + listOf(7 to "a", 8 to "b", 9 to "c").map { (i, pk) -> Member(i, "Server $pk", "server", pk, points.first { it.first == i }.second) }

    /** The check round as the phone runs it: its pending shares and one server's, over that group. */
    private fun checkRound(group: String, msg: String, mine: List<Pair<Int, String>>, theirs: List<Pair<Int, String>>): String? = try {
        val all = mine + theirs
        val cs = all.map { (i, s) -> i to (Json.parse(FrostNative.commit(group, i, s)) as Map<*, *>) }
        val commits = Json.stringify(cs.map { it.second["commit"] })
        val zs = all.zip(cs).map { (sh, c) -> listOf(sh.first, FrostNative.sign(group, sh.first, sh.second, c.second["nonces"] as String, msg, commits)) }
        FrostNative.aggregate(group, msg, commits, Json.stringify(zs))
    } catch (_: Exception) { null }

    private fun refreshTo(key: Map<String, Dkg.Result>, epoch: Int, drop: List<Int>): Map<String, Refresh.Result> {
        val left = key["p"]!!.members.filter { it.first !in drop }
        val owner = holders.toMap()
        val plan = Json.parse(Json.stringify(mapOf("epoch" to epoch, "threshold" to 4, "dealers" to listOf("p", "a"), "periodic" to true,
            "holders" to left.map { mapOf("idx" to it.first, "pk" to owner[it.first]) },
            "points" to left.map { listOf(it.first, it.second) }) + if (drop.isEmpty()) emptyMap() else mapOf("drop" to drop))) as Map<*, *>
        val who = listOf("p", "a", "b", "c").filter { pk -> left.any { owner[it.first] == pk } }
        val q = ArrayDeque<Triple<String, String, String>>()
        val out = HashMap<String, Refresh.Result>()
        val runs = who.associateWith { pk -> Refresh(plan, pk, key[pk]!!.shares.filter { it.first !in drop }, { to, m -> q.add(Triple(pk, to, Json.stringify(m))) }, { out[pk] = it }, SystemEnv) }
        repeat(10) { runs.values.forEach { it.tick() }; while (q.isNotEmpty()) { val (f, t, m) = q.removeFirst(); runs[t]?.take(Json.parse(m) as Map<*, *>, f) } }
        return out
    }

    @Test fun theCheckRoundSignsWithThePendingShares() {
        val key = makeKey()
        val groupX = key["p"]!!.groupX
        val pending = refreshTo(key, 1, emptyList())
        val points = pending["p"]!!.points
        val group = Signer.Quietly.pendingGroup(groupX, 4, members(key["p"]!!.members), points, emptyList())
        val msg = Signer.Quietly.checkMessage(groupX, 1)
        // The phone's three pending shares and one server's: four points, the threshold.
        val sig = checkRound(group, msg, pending["p"]!!.shares, pending["a"]!!.shares)
        assertTrue("the check round made no signature", sig != null)
        assertTrue("the signature isn't by this key", Secp256k1.verifySchnorr(sig!!.hexToBytes(), msg.hexToBytes(), groupX.hexToBytes()))
        // The message is this key's and this epoch's, and nothing else.
        assertEquals(msg, Signer.Quietly.checkMessage(groupX, 1))
        assertFalse(msg == Signer.Quietly.checkMessage(groupX, 2))
    }

    @Test fun theCurrentSharesCannotSignTheCheckOfTheEpochToCome() {
        val key = makeKey()
        val groupX = key["p"]!!.groupX
        val pending = refreshTo(key, 1, emptyList())
        val group = Signer.Quietly.pendingGroup(groupX, 4, members(key["p"]!!.members), pending["p"]!!.points, emptyList())
        val msg = Signer.Quietly.checkMessage(groupX, 1)
        // The old shares against the new points: no signature, so a server that kept its old
        // ones can never pass the check that lets an epoch be committed.
        val sig = checkRound(group, msg, key["p"]!!.shares, key["a"]!!.shares)
        assertTrue("the old shares signed the new epoch's check", sig == null || !Secp256k1.verifySchnorr(sig.hexToBytes(), msg.hexToBytes(), groupX.hexToBytes()))
    }

    @Test fun aSwappedOutServerIsLeftOutOfTheEpochAndHoldsNothingThatFits() {
        val key = makeKey()
        val groupX = key["p"]!!.groupX
        // Server 9 has gone: the others move to epoch 1 without it.
        val pending = refreshTo(key, 1, listOf(9))
        val group = Signer.Quietly.pendingGroup(groupX, 4, members(key["p"]!!.members), pending["p"]!!.points, listOf(9))
        assertFalse("the group still has the server that went", group.contains("\"idx\":9"))
        val msg = Signer.Quietly.checkMessage(groupX, 1)
        // The phone and either of the two left still sign the check.
        for (s in listOf("a", "b")) {
            val sig = checkRound(group, msg, pending["p"]!!.shares, pending[s]!!.shares)
            assertTrue("the phone and server $s couldn't check the new epoch", sig != null && Secp256k1.verifySchnorr(sig.hexToBytes(), msg.hexToBytes(), groupX.hexToBytes()))
        }
        // What the one that went holds is of the old epoch: with the phone's new shares it
        // combines with nothing.
        val sig = checkRound(group, msg, pending["p"]!!.shares, key["c"]!!.shares)
        assertTrue("the server that went could still take part", sig == null || !Secp256k1.verifySchnorr(sig.hexToBytes(), msg.hexToBytes(), groupX.hexToBytes()))
    }
}
