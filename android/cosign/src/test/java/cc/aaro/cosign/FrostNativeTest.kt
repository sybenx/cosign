package cc.aaro.cosign

import cc.aaro.cosign.core.FrostNative
import cc.aaro.cosign.core.hexToBytes
import fr.acinq.secp256k1.Secp256k1
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The phone's native FROST: shares from the earlier dealer sign, and the result is plain BIP-340. */
class FrostNativeTest {
    private val v = JSONObject(javaClass.classLoader!!.getResource("frost.json")!!.readText())
    private val shares = v.getJSONArray("shares").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
    private val group = JSONObject().put("groupX", v.getString("groupX")).put("threshold", 2)
        .put("members", JSONArray(shares.map { JSONObject().put("idx", it.getInt("idx")).put("sharePub", it.getString("pub")) })).toString()
    private fun secret(idx: Int) = shares.first { it.getInt("idx") == idx }.getString("secret")

    @Test fun everyPairSigns() {
        for ((a, b) in listOf(1 to 3, 2 to 3, 1 to 2)) {
            val msg = "%064x".format(a * 10 + b)
            val ca = JSONObject(FrostNative.commit(group, a, secret(a)))
            val cb = JSONObject(FrostNative.commit(group, b, secret(b)))
            val commits = JSONArray(listOf(ca.getJSONObject("commit"), cb.getJSONObject("commit"))).toString()
            val za = FrostNative.sign(group, a, secret(a), ca.getString("nonces"), msg, commits)
            val zb = FrostNative.sign(group, b, secret(b), cb.getString("nonces"), msg, commits)
            assertTrue(FrostNative.verifyPartial(group, msg, commits, b, zb))
            assertFalse(FrostNative.verifyPartial(group, msg, commits, a, zb))
            val sig = FrostNative.aggregate(group, msg, commits, JSONArray(listOf(JSONArray(listOf(a, za)), JSONArray(listOf(b, zb)))).toString())
            assertTrue("pair $a,$b", Secp256k1.verifySchnorr(sig.hexToBytes(), msg.hexToBytes(), v.getString("groupX").hexToBytes()))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun someoneElsesShareIsRefused() { FrostNative.commit(group, 1, secret(2)) }
}
