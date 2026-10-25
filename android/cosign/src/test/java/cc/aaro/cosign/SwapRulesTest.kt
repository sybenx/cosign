package cc.aaro.cosign

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What may be done about a server the others say has gone (COSIGN.md §7.7, and the rules the
 * user set): a quiet swap is for public servers on an account with servers to spare. A server
 * someone runs themselves is never taken out from under them — far more likely unplugged for a
 * week than gone — an account with two servers is never thinned, and no key ever goes below two.
 */
class SwapRulesTest {
    private fun server(idx: Int, name: String = "Server $idx") = Member(idx, name, "server", "pk$idx", "x")
    /** The key's servers, which is what the choice is made from: its phone and paper don't count. */
    private val three = listOf(server(4), server(5), server(6))

    @Test fun aPublicServerOnAnAccountWithThreeIsSwappedOut() {
        assertEquals(listOf(Signer.Swap.Choice.TakeOut(6)), Signer.Swap.choose(listOf(6), three, emptyList()))
    }

    @Test fun aServerYouRunYourselfIsNeverTakenOutBehindYourBack() {
        assertEquals(listOf(Signer.Swap.Choice.Tell(6)), Signer.Swap.choose(listOf(6), three, listOf("pk6")))
        // Someone else's, on the same account, still goes.
        assertEquals(listOf(Signer.Swap.Choice.TakeOut(5)), Signer.Swap.choose(listOf(5), three, listOf("pk6")))
    }

    @Test fun anAccountWithTwoServersIsNeverThinned() {
        val two = listOf(server(4), server(5))
        assertEquals(listOf(Signer.Swap.Choice.Tell(5)), Signer.Swap.choose(listOf(5), two, emptyList()))
    }

    @Test fun aKeyNeverGoesBelowTwoServers() {
        // Two of three gone at once: taking both would leave one, so the person is told instead.
        assertEquals(listOf(Signer.Swap.Choice.Tell(5), Signer.Swap.Choice.Tell(6)), Signer.Swap.choose(listOf(5, 6), three, emptyList()))
        // Four servers, two gone: two are left, so they go.
        val four = three + server(7)
        assertEquals(listOf(Signer.Swap.Choice.TakeOut(5), Signer.Swap.Choice.TakeOut(6)), Signer.Swap.choose(listOf(5, 6), four, emptyList()))
    }

    @Test fun nothingToDoWhenNobodyIsGone() {
        assertEquals(listOf(Signer.Swap.Choice.Nothing), Signer.Swap.choose(emptyList(), three, emptyList()))
        // A server the key doesn't have is nothing to act on.
        assertEquals(listOf(Signer.Swap.Choice.Nothing), Signer.Swap.choose(listOf(99), three, emptyList()))
    }
}
