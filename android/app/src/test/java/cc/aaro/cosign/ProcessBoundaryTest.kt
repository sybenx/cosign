package cc.aaro.cosign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The line between the two processes (Proc.kt), checked in the source: the manifest puts
 * everything that holds or uses the key in ":signer", the code that runs in the main process
 * never names key material, and the signer's code never names the feed, pictures or video.
 * At run time, Secrets, FROST and Signers refuse to load outside the signer (Proc.signerOnly).
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

    /** Runs in both: which process this is, and the Application that sets each one up. */
    private val either = listOf("Proc.kt", "CosignApp.kt", "Startup.kt")
    /** Runs only in the signer process. */
    private val signerOnly = listOf("Phone.kt", "Signers.kt", "SignerService.kt", "SignerActivity.kt", "Secrets.kt", "Lists.kt",
        "CosignService.kt", "Nip55Activity.kt", "Nip55Provider.kt", "Push.kt", "DecisionReceiver.kt", "BootReceiver.kt",
        "net/Relays.kt", "net/Servers.kt", "net/Transfer.kt", "net/Store.kt")

    /** Everything else runs in the main process (a new screen too, without being listed here): the UI, the feed, what both draw. */
    private val mainSide get() = src.walk().filter { it.isFile && it.name.endsWith(".kt") }.map { it.relativeTo(src).path }
        .filter { it !in signerOnly && it !in either && !it.startsWith("core/") }.toList()

    @Test fun mainProcessCodeNeverNamesKeyMaterial() {
        assertTrue("ui/Discover.kt" in mainSide && "ui/Screens.kt" in mainSide)
        for (f in mainSide) {
            val hits = keyMaterial.findAll(read(f)).map { it.value }.toSet()
            assertTrue("$f names ${hits.joinToString()}", hits.isEmpty())
        }
    }

    @Test fun signerCodeNeverNamesTheFeed() {
        for (f in signerOnly + File(src, "core").list()!!.filter { it.endsWith(".kt") }.map { "core/$it" }) {
            val hits = untrusted.findAll(read(f)).map { it.value }.toSet()
            assertTrue("$f names ${hits.joinToString()}", hits.isEmpty())
        }
    }

    @Test fun manifestPutsTheKeyInTheSignerProcess() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val components = Regex("""<(activity|service|provider|receiver)\b([^>]*)>""").findAll(manifest)
            .associate { m -> Regex("""android:name="([^"]+)"""").find(m.groupValues[2])!!.groupValues[1] to Regex("""android:process="([^"]+)"""").find(m.groupValues[2])?.groupValues?.get(1) }
        for (c in listOf(".SignerService", ".SignerActivity", ".Nip55Activity", ".Nip55Provider", ".CosignService", ".DecisionReceiver", ".Push", ".BootReceiver"))
            assertEquals(c, ":signer", components[c])
        assertEquals("the UI", null, components[".MainActivity"])
        // The signer is reachable from other apps only through NIP-55; SignerService is the app's own.
        assertTrue(Regex("""android:name="\.SignerService"\s+android:process=":signer"\s+android:exported="false"""").containsMatchIn(manifest))
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
