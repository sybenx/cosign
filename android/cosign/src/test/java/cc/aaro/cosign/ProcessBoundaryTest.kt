package cc.aaro.cosign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The line between the two processes (Proc.kt), checked in the library's source: its manifest
 * puts what holds or uses the key in ":signer", its main-process side (the UI's client) never
 * names key material, and none of it names the feed, pictures or video. At run time, Secrets,
 * FROST and Signers refuse to load outside the signer (Proc.signerOnly). The app that uses the
 * library checks its own side the same way.
 */
class ProcessBoundaryTest {
    private val src = File("src/main/java/cc/aaro/cosign")
    private fun read(path: String) = File(src, path).readText()
        // Comments may name anything.
        .replace(Regex("""/\*[\s\S]*?\*/"""), "").replace(Regex("""//[^\n]*"""), "")

    /** What holds or uses a share. */
    private val keyMaterial = Regex("""\b(Signer|Signers|Secrets|FrostNative|Frost\.(sign|commit|ecdh\w*|aggregate)|Lists|Relays|Dkg|Refresh|Backup|signers)\b""")
    /** What shows strangers' posts, pictures and video. */
    private val untrusted = Regex("""\b(Social|People|Sources|Fetch|Images|Translate|Places|TubeFeed|ExoPlayer|WebView|media3|Coil|instance\.accounts)\b""")

    /** Runs in the main process: the UI's side of the signer. */
    private val mainSide = listOf("SignerClient.kt")
    private val all get() = src.walk().filter { it.isFile && it.name.endsWith(".kt") }.map { it.relativeTo(src).path }.toList()

    @Test fun mainProcessCodeNeverNamesKeyMaterial() {
        for (f in mainSide) {
            val hits = keyMaterial.findAll(read(f)).map { it.value }.toSet()
            assertTrue("$f names ${hits.joinToString()}", hits.isEmpty())
        }
    }

    @Test fun libraryNeverNamesTheFeed() {
        assertTrue("Phone.kt" in all && "core/Frost.kt" in all)
        for (f in all) {
            val hits = untrusted.findAll(read(f)).map { it.value }.toSet()
            assertTrue("$f names ${hits.joinToString()}", hits.isEmpty())
        }
    }

    @Test fun manifestPutsTheKeyInTheSignerProcess() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val components = Regex("""<(activity|service|provider|receiver)\b([^>]*)>""").findAll(manifest)
            .associate { m -> Regex("""android:name="([^"]+)"""").find(m.groupValues[2])!!.groupValues[1] to Regex("""android:process="([^"]+)"""").find(m.groupValues[2])?.groupValues?.get(1) }
        assertEquals(setOf("cc.aaro.cosign.SignerService", "cc.aaro.cosign.Nip55Provider"), components.keys)
        for (c in components.keys) assertEquals(c, ":signer", components[c])
        // The signer is reachable from other apps only through NIP-55; SignerService is the app's own.
        assertTrue(Regex("""android:name="cc\.aaro\.cosign\.SignerService"\s+android:process=":signer"\s+android:exported="false"""").containsMatchIn(manifest))
    }

    @Test fun theUiNeverGetsASecret() {
        val m = Membership("aa".repeat(32), 1, listOf(Share(1, "bb".repeat(32)), Share(2, "cc".repeat(32))), "dd".repeat(32),
            Group("ee".repeat(32), "npub1x", 4, listOf("wss://r"), emptyList()))
        val u = Ui(member = m, offer = Offer("ff", "t", 1, "11".repeat(32), "dd", m.group), paper = "cosign:backup?k=" + "22".repeat(32),
            takeOut = TakeOut(TakeOut.Stage.SHOWING, nsec = "nsec1secret"))
        val sent = Wire.read(Wire.write(SignerService.forUi(u)))
        val all = sent.toString()
        for (secret in listOf("aa".repeat(32), "bb".repeat(32), "cc".repeat(32), "11".repeat(32), "22".repeat(32), "nsec1secret"))
            assertTrue("leaks $secret", secret !in all)
        // What the UI does need is still there.
        assertEquals(m.group, sent.member?.group)
        assertEquals(listOf(1, 2), sent.member?.idxs)
        assertEquals("", sent.paper)
        assertEquals(TakeOut.Stage.SHOWING, sent.takeOut?.stage)
    }
}
