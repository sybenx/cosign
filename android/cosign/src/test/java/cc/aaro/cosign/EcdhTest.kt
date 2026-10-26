package cc.aaro.cosign

import cc.aaro.cosign.Signer.Ecdh
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Reading what a server said to a request for several counterparties (COSIGN.md §5.6). The
 * point of the shape is that servers of different ages all make sense: one that knows `peers`
 * answers for each, and one that doesn't answers the first by itself, which is how this phone
 * knows to ask on for the rest instead of thinking it has them.
 */
class EcdhTest {
    private val a = "a".repeat(64); private val b = "b".repeat(64); private val c = "c".repeat(64)
    private val asked = listOf(a, b, c)

    @Test fun aServerThatKnowsPeersAnswersForEach() {
        val res = mapOf("ok" to true, "points" to listOf("01"), "point" to "01",
            "many" to listOf(mapOf("peerX" to a, "points" to listOf("0a")), mapOf("peerX" to b, "points" to listOf("0b"))))
        assertEquals(listOf(a to listOf("0a"), b to listOf("0b")), Ecdh.rows(res, asked))
    }

    @Test fun anOlderServerAnswersTheFirstOnly() {
        // No `many`: what we get is the first one we asked for, and the rest are still to ask.
        assertEquals(listOf(a to listOf("0a", "0b")), Ecdh.rows(mapOf("ok" to true, "points" to listOf("0a", "0b")), asked))
        // Older still: a single point.
        assertEquals(listOf(a to listOf("0a")), Ecdh.rows(mapOf("ok" to true, "point" to "0a"), asked))
    }

    @Test fun whatWeDidNotAskForIsIgnored() {
        val res = mapOf("ok" to true, "many" to listOf(
            mapOf("peerX" to a, "points" to listOf("0a")),
            mapOf("peerX" to "d".repeat(64), "points" to listOf("0d")), // nobody asked about this one
            mapOf("peerX" to a, "points" to listOf("09")),              // nor twice about this one
        ))
        assertEquals(listOf(a to listOf("0a")), Ecdh.rows(res, asked))
    }

    @Test fun nonsenseGivesNothingRatherThanAWrongAnswer() {
        assertEquals(emptyList<Pair<String, List<String>>>(), Ecdh.rows(mapOf("ok" to true), asked))
        assertEquals(emptyList<Pair<String, List<String>>>(), Ecdh.rows(mapOf("many" to listOf(mapOf("peerX" to a))), asked))
        assertEquals(emptyList<Pair<String, List<String>>>(), Ecdh.rows(mapOf("points" to listOf("0a")), emptyList()))
    }
}
