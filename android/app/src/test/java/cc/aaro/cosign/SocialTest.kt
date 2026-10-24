package cc.aaro.cosign

import cc.aaro.cosign.core.Event
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** What the home screen's search box opens, and how it reads a reply's place in a thread. */
class SocialTest {
    private val fiatjaf = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    private val note = "9739a916c3b6acb295231ed16654fd1e6379fe214eddec360c4514b495f259c9"

    @Test fun identifiersOpenWhatTheyName() {
        assertEquals(Ref.Profile(fiatjaf), Ref.parse("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"))
        assertEquals(Ref.Profile(fiatjaf), Ref.parse(" nostr:npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6 "))
        assertEquals(Ref.Profile(fiatjaf), Ref.parse(fiatjaf.uppercase()))
        // Longer than plain bech32's 90 characters, with relays inside.
        assertEquals(Ref.Profile(fiatjaf), Ref.parse("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpz3mhxue69uhhyetvv9ujuerpd46hxtnfduqs6amnwvaz7tmwdaejumr0dsfg70ls"))
        assertEquals(Ref.Note(note), Ref.parse("nevent1qqsfwwdfzmpmdt9jj533a5tx2n73ucmelcs5ah0vxcxy2995jhe9njgpz3mhxue69uhhyetvv9ujuerpd46hxtnfduy3kz48"))
        assertNull(Ref.parse("bitcoin"))
        assertNull(Ref.parse("#nostr"))
        assertNull(Ref.parse("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7")) // bad checksum
    }

    private fun ev(vararg tags: List<String>) = Event(fiatjaf, 0, 1, tags.toList(), "")

    @Test fun repliesFindTheirPlace() {
        val root = "a".repeat(64); val parent = "b".repeat(64); val quoted = "c".repeat(64)
        // Marked tags (NIP-10).
        val marked = ev(listOf("e", root, "", "root"), listOf("e", parent, "", "reply"))
        assertEquals(parent, parentOf(marked)); assertEquals(root, rootOf(marked))
        // A direct reply to the first note carries only the root marker.
        assertEquals(root, parentOf(ev(listOf("e", root, "", "root"))))
        // The old positional form: first is the root, last is the parent.
        val positional = ev(listOf("e", root), listOf("e", parent))
        assertEquals(parent, parentOf(positional)); assertEquals(root, rootOf(positional))
        // A note that only mentions another is no reply.
        assertNull(parentOf(ev(listOf("e", quoted, "", "mention"))))
        assertNull(parentOf(ev(listOf("p", fiatjaf))))
    }
}
