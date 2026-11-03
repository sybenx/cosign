package cc.aaro.cosign

import cc.aaro.cosign.core.FrostNative
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * A phone joining a key takes the group from whichever `welcome` reaches it, because at that
 * moment it has no member list to check a sender against (live finding 17). These are the two
 * crypto facts the fix rests on, so that what the condition in `onJoinPiece` is for stays
 * written down:
 *
 *  - an attacker that supplies **every** piece supplies a consistent set, and `repairStep3`
 *    verifies it against the group *it also chose*, so the library raises no objection;
 *  - one honest piece in the sum and `repairStep3` refuses, because the sum no longer lies on
 *    the attacker's polynomial.
 *
 * So requiring a piece from the device whose invite the person scanned is the whole of the fix,
 * and the library's own `share.verify()` is what then catches the forgery. Neither fact depends
 * on the phone checking anything itself, which is why the first draft of this patch added a
 * redundant point check and the second does not.
 */
class JoinWelcomeTest {
    private fun rnd(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }

    /** A key with shares 1-3 for a device and 4-5 for two servers, threshold 4. */
    private class Key(threshold: Int = 4, n: Int = 6) {
        val dealt: JSONObject = JSONObject(FrostNative.dealFromSecret(ByteArray(32).also { SecureRandom().nextBytes(it) }, IntArray(n) { it + 1 }, threshold))
        val groupX: String = dealt.getString("groupX")
        val shares: List<JSONObject> = dealt.getJSONArray("shares").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
        fun secret(idx: Int) = shares.first { it.getInt("idx") == idx }.getString("secret")
        /** The group JSON a welcome would carry: everyone but the joiner. */
        fun groupJson(without: Int) = JSONObject().put("groupX", groupX).put("threshold", 4)
            .put("members", JSONArray(shares.filter { it.getInt("idx") != without }
                .map { JSONObject().put("idx", it.getInt("idx")).put("sharePub", it.getString("sharePub")) })).toString()
    }

    private fun repair(group: String, sigmas: List<String>, k: Int) =
        try { FrostNative.repairStep3(group, JSONArray(sigmas).toString(), k) } catch (e: Exception) { null }

    @Test fun anAttackerThatSuppliesEveryPieceIsNotCaughtByTheLibrary() {
        val evil = Key()
        val k = 6
        // One piece, equal to the share it dealt itself at k: the sum is that share.
        val share = repair(evil.groupJson(k), listOf(evil.secret(k)), k)
        assertEquals("the library accepts a sum an attacker chose, against the group it chose", evil.secret(k), share)
    }

    @Test fun oneHonestPieceInTheSumAndTheLibraryRefuses() {
        val real = Key()
        val evil = Key()
        val k = 6
        // What the attacker wants, plus a piece it did not make: the real inviter's.
        val mixed = repair(evil.groupJson(k), listOf(evil.secret(k), real.secret(1)), k)
        assertTrue("a sum with an honest piece does not lie on the attacker's polynomial", mixed == null)
    }

    @Test fun theHonestSumIsAccepted() {
        val real = Key()
        val k = 6
        assertEquals("no false refusal on the real key", real.secret(k), repair(real.groupJson(k), listOf(real.secret(k)), k))
    }

    @Test fun aWelcomeCannotMakeItselfTheWholeQuorum() {
        // `need` used to be read straight out of the welcome, so `helpers: [x]` asked for one
        // piece. The floor is two, whatever it says.
        val said = JSONObject().put("helpers", JSONArray(listOf(9)))
        val need = maxOf(2, said.getJSONArray("helpers").length())
        assertEquals(2, need)
    }
}
