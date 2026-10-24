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

    @Test fun approvalsAskAboutWhatHappens() {
        val q = { s: String -> cc.aaro.cosign.ui.question(s) }
        assertEquals("Unfollow 10 people?", q("Remove 10 of your 30 follows"))
        assertEquals("Unfollow 30 people and follow 30 people instead?", q("Remove 30 of your 30 follows (and add 30)"))
        assertEquals("Unfollow all 3 people?", q("Empty your follow list (it has 3 follows)"))
        assertEquals("Delete 5 posts?", q("Delete 5 of your events"))
        assertEquals("Delete 5 posts?", q("Delete 5 events for Approval test")) // a batch, as your servers word it
        assertEquals("Delete your follow list?", q("Delete your follow list"))
        assertEquals("Remove all 4 bookmarks from your bookmarks?", q("Empty your bookmarks (it has 4 bookmarks)"))
        assertEquals("Remove all 5 people from your follow set?", q("Empty your follow set (it has 5 persons)"))
        assertEquals("Clear your profile (picture, about)?", q("Wipe your profile: picture, about"))
        assertEquals("Erase everything you've ever posted?", q("Ask relays to erase everything you have ever published"))
        assertEquals("Allow a note dated 2099-01-01?", q("Note dated in the future (2099-01-01)"))
        assertEquals("Remove 2 of your 3 relays?", q("Remove 2 of your 3 relays"))
    }

    private fun note(text: String, vararg tags: List<String>) = Event(fiatjaf, 0, 1, tags.toList(), text)

    @Test fun languagesAreGuessedOnlyWhenClear() {
        assertEquals(setOf("en"), Lang.guess("I think this is the best thing that happened to my week, and you should try it"))
        assertEquals(setOf("pt"), Lang.guess("Eu não sei o que fazer com isso, mas você tem razão sempre"))
        assertEquals(setOf("de"), Lang.guess("Ich bin nicht sicher, aber das ist auch eine gute Idee für uns"))
        assertEquals(setOf("es"), Lang.guess("No sé qué hacer con esto, pero también es muy bueno para la gente"))
        assertEquals("ja", Lang.guess("今日はとても良い天気ですね。散歩に行きましょう")?.first())
        assertEquals(true, Lang.guess("Привет всем, как у вас дела сегодня?")?.contains("ru"))
        assertNull(Lang.guess("GM ☀️"))                          // too short to tell
        assertNull(Lang.guess("https://example.com/a.jpg #nostr")) // nothing but a link and a tag
        val en = setOf("en")
        assertEquals(true, Lang.readable(note("Eu não sei o que fazer com isso", listOf("l", "en", "ISO-639-1")), en)) // its label wins
        assertEquals(false, Lang.readable(note("Eu não sei o que fazer com isso, mas você tem razão sempre"), en))
        assertEquals(true, Lang.readable(note("Bitcoin 🚀🚀"), en))
    }

    @Test fun sensitiveNotesAreFlagged() {
        assertEquals(true, Safety.flagged(note("look", listOf("content-warning", "spoilers"))))
        assertEquals(true, Safety.flagged(note("hi", listOf("t", "NSFW"))))
        assertEquals(true, Safety.flagged(note("new pics #nsfw")))
        assertEquals(true, Safety.flagged(note("x", listOf("l", "NS-nud", "content-warning"))))
        assertEquals(false, Safety.flagged(note("#nsfwish is not a tag we know")))
        assertEquals(false, Safety.flagged(note("a calm note", listOf("t", "nature"))))
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
