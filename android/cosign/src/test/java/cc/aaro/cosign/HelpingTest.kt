package cc.aaro.cosign

import cc.aaro.cosign.Signer.Helping
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Who this phone gives a piece of a decryption to (COSIGN.md §5.6). Your own devices, because
 * one of them coordinating a decryption is you reading your own messages and it already holds
 * as much of your key as this phone does. Not a server: a server never coordinates one, so a
 * server asking is something else wanting to read your messages, and nothing here asked for it.
 */
class HelpingTest {
    @Test fun yourOwnDevicesMay() {
        assertTrue(Helping.helps("phone"))
        assertTrue(Helping.helps("device"))
    }

    @Test fun aServerMayNot() {
        assertFalse("a server asked and was helped", Helping.helps("server"))
    }

    @Test fun norThePaperNorAnythingElse() {
        assertFalse(Helping.helps("backup"))
        assertFalse(Helping.helps(null))
        assertFalse(Helping.helps(""))
    }

    /**
     * Asking a server for a piece is the other direction and must keep working: it is how this
     * phone, the extension and the Mac app read messages at all. The request carries the app's
     * grant, which is what the server checks.
     */
    @Test fun askingAServerIsUntouched() {
        val src = File("src/main/java/cc/aaro/cosign/Phone.kt").readText()
        val asks = Regex("""ecdh_req"[\s\S]{0,400}?"grant" to""").containsMatchIn(src)
        assertTrue("this phone no longer asks servers for a piece, with its grant", asks)
        // And the refusal says which way round it is, in words a person can read.
        assertTrue(src.contains("your devices read your messages, your servers don't") ||
            src.contains("your devices read your messages, your servers don’t"))
    }
}
