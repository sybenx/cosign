package cc.aaro.cosign

import cc.aaro.cosign.Signer.Asking
import cc.aaro.cosign.Signer.Asking.Outcome
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What a round of asking every server comes to. A server that was away when an app connected
 * hasn't heard of it yet — the servers pass grants on as they catch up — so its "revoked" is
 * its own word. Taking it for the account's was the bug behind an app that one server didn't
 * know breaking everywhere, and the phone forgetting the app's access altogether.
 */
class AskingTest {
    @Test fun oneServerThatHasNotHeardOfTheAppIsNotTheAccountsAnswer() {
        // One says revoked, another simply didn't answer: nothing is settled, so the app keeps
        // its access and the person is told the servers couldn't be reached.
        assertEquals(Outcome.REFUSED, Asking.outcome(listOf("revoked: that app no longer has access", null)))
    }

    @Test fun onlyWhenEveryServerThatAnsweredSaysSo() {
        assertEquals(Outcome.REVOKED_EVERYWHERE, Asking.outcome(listOf("revoked: that app no longer has access")))
        assertEquals(Outcome.REVOKED_EVERYWHERE, Asking.outcome(listOf("revoked: a", "revoked: b")))
        // One of them quiet settles nothing, however many of the others agree.
        assertEquals(Outcome.REFUSED, Asking.outcome(listOf("revoked: a", "revoked: b", null)))
    }

    @Test fun anythingElseIsARefusal() {
        assertEquals(Outcome.REFUSED, Asking.outcome(listOf("refused: that would delete your follows")))
        assertEquals(Outcome.REFUSED, Asking.outcome(listOf("revoked: a", "bad request")))
    }

    @Test fun silenceFromEveryoneIsNotAnAnswer() {
        assertEquals(Outcome.NOBODY_ANSWERED, Asking.outcome(listOf(null, null)))
        assertEquals(Outcome.NOBODY_ANSWERED, Asking.outcome(emptyList()))
    }
}
