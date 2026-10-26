package cc.aaro.cosign

import cc.aaro.cosign.Signer.Kept
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import java.io.File

/**
 * The conversation keys kept in memory (COSIGN.md §5.6). Each one takes a server to work out,
 * so they are kept while the phone is awake — and when they go, they are wiped rather than
 * dropped, because dropping leaves them in memory for whatever reads it next.
 */
class KeptTest {
    private fun secret(b: Byte) = ByteArray(32) { b }

    @Test fun keptUntilForgotten() {
        val k = Kept()
        val x = secret(7)
        k["alice"] = x
        assertSame(x, k["alice"])
        assertEquals(1, k.size)
        assertNull("something nobody asked about", k["bob"])
    }

    @Test fun forgettingWipesWhatItHeld() {
        val k = Kept()
        val alice = secret(7); val bob = secret(9)
        k["alice"] = alice; k["bob"] = bob
        assertEquals(2, k.forgetAll())
        assertEquals(0, k.size)
        assertNull(k["alice"])
        // Not merely dropped: what was in memory is zeros now.
        assertArrayEquals(ByteArray(32), alice)
        assertArrayEquals(ByteArray(32), bob)
    }

    @Test fun replacingOneWipesTheOldOne() {
        val k = Kept()
        val first = secret(1)
        k["alice"] = first
        k["alice"] = secret(2)
        assertArrayEquals(ByteArray(32), first)
    }

    /**
     * Where they are thrown away. A unit test can't drive a whole signer, so this checks the
     * wiring in the source: an app losing its access, this phone being reported lost, and the
     * screen going off each forget everything kept.
     */
    @Test fun everythingThatEndsAccessForgetsThem() {
        val src = File("src/main/java/cc/aaro/cosign/Phone.kt").readText()
        fun calls(what: String, within: String) {
            val at = src.indexOf(within)
            assert(at > 0) { "$within is gone from Phone.kt" }
            // Around it, not after it: a receiver's body is written before the thing it listens for.
            val near = src.substring(maxOf(0, at - 600), minOf(src.length, at + 1200))
            assert(near.contains("sharedXs.forgetAll()")) { "$what doesn't forget the conversation keys" }
        }
        calls("removing an app", "fun removeSite(")
        calls("undoing everything an app did", "fun confirmUndoSite(")
        calls("this phone reported lost", "\"removed\" ->")
        calls("the screen going off", "ACTION_SCREEN_OFF")
        calls("every server saying an app has no access", "Outcome.REVOKED_EVERYWHERE")
        // And nothing writes them down: they live in memory only.
        assert(!src.contains("saveSharedX") && !Regex("""sharedXs[^\n]*(save|putString|edit\(\))""").containsMatchIn(src)) { "a conversation key is being written down" }
    }
}
