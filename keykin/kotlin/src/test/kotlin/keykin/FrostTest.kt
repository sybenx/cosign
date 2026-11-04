package keykin

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class FrostTest {
    @Test fun dkgAndSign() {
        val (g, C, shares) = Frost.dkgLocal(listOf(1, 2, 3, 4, 5, 6, 7, 8))
        for ((i, s) in shares) assertTrue(mul(s) == derive(C, java.math.BigInteger.valueOf(i)))
        val msg = hex(sha(utf8("kotlin signs")))
        val signers = listOf(1L, 2L, 3L, 4L)
        val cs = signers.map { Frost.commit(C, it, shares[it]!!, Frost.hedge(shares[it]!!, utf8("ctx$it"))) }
        val zs = cs.map { it.i to Frost.sign(C, it, shares[it.i]!!, msg, cs) }
        for ((i, z) in zs) assertTrue(Frost.verifyShare(C, msg, cs, i, z))
        assertFalse(Frost.verifyShare(C, msg, cs, 4, zs[0].second), "a partial is checked against its own P_i")
        val sig = Frost.aggregate(C, msg, cs, zs)
        assertTrue(schnorrVerify(sig, unhex(msg), g), "a plain BIP-340 signature under g")
    }
}
