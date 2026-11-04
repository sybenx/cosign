package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The Kotlin Guard (Device policy §2, §3, §6) on a device restored from a TS snapshot (vectors/grants.json's). */
class GuardTest {
    private val v = JSONObject(File(System.getProperty("keykin.grants")).readText())
    private fun device() = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
    private fun follows(n: Int, from: Int = 0) = (0 until n).map { listOf("p", (it + from).toString(16).padStart(64, '0')) }
    /** An event as the account signed it (the guard records what servers co-signed; the signature isn't its job). */
    private fun signed(d: Device, kind: Int, tags: List<List<String>>, at: Long, content: String = ""): Event {
        val u = Unsigned(d.g, at, kind, tags, content); return Event(u.id, d.g, at, kind, tags, content, "00".repeat(64))
    }

    @Test fun cardsAutoDeclinesAndRecords() {
        val d = device(); val g = d.guard; val site = "${d.pub}:site"
        g.signed(signed(d, 3, follows(40), d.now - 8 * 86400), "member")
        assertEquals(40, d.history.current("3")!!.tags.size)
        // A cut of 15: a card; the person allows it, and it becomes the site's last-approved version.
        var shown = 0
        g.onCard = { c -> shown++; g.answer(c.id, if (shown == 1) "allow" else "decline") }
        val cut = Unsigned(d.g, d.now, 3, follows(25), "")
        assertEquals("sign", g.gate(cut, site, listOf("lists")).ok)
        g.signed(signed(d, 3, follows(25), d.now), site)
        assertEquals(cut.id, d.meta.evidence().ledger.approvedOf(site, "3")?.first)
        assertEquals(15, d.meta.evidence().ledger.removals(site, "3").size)
        // Three declines of the same row: that row is declined for an hour without a card.
        for (k in 0 until 3) assertTrue(g.gate(Unsigned(d.g, d.now + k + 1, 3, follows(10 - k), ""), site, listOf("lists")).error!!.startsWith("declined: you declined it"))
        assertTrue(g.gate(Unsigned(d.g, d.now + 5, 3, follows(5), ""), site, listOf("lists")).error!!.startsWith("declined: you declined this site"))
        assertEquals(4, shown)
        // In the background (no one to ask), a Confirm is neither signed nor refused: the app opens its screen.
        val bg = g.gate(Unsigned(d.g, d.now, 3, follows(10), ""), "${d.pub}:other", listOf("lists"), wait = false)
        assertEquals(null, bg.ok)
    }

    @Test fun singleDeletionWaitsForUndo() {
        val d = device(); val g = d.guard; val site = "${d.pub}:site"; g.undoMs = 200
        val post = signed(d, 1, emptyList(), d.now - 10, "oops"); g.signed(post, site)
        val del = Unsigned(d.g, d.now, 5, listOf(listOf("e", post.id)), "")
        assertEquals("undo", g.judge(del, site, listOf("post")).level)
        assertEquals("sign", g.gate(del, site, listOf("post")).ok, "signed once the wait passed")
        val t = Thread { Thread.sleep(50); g.pendingUndos().firstOrNull()?.let { g.undoPending(it.id) } }; t.start()
        assertEquals("declined: undone", g.gate(del, site, listOf("post")).error)
        t.join()
        // Another's post: Confirm, and a held one stays Held.
        val other = signed(d, 1, emptyList(), d.now - 9, "theirs"); g.signed(other, "member")
        assertEquals("delete-other", g.judge(Unsigned(d.g, d.now, 5, listOf(listOf("e", other.id)), ""), site, listOf("post")).row)
        assertEquals("held", g.gate(Unsigned(d.g, d.now, 5, follows(5).map { listOf("e", it[1]) }, ""), site, listOf("post")).ok)
    }

    @Test fun review18() {
        val d = device(); val g = d.guard; val site = "${d.pub}:site"; g.undoMs = 300
        val post = signed(d, 1, emptyList(), d.now - 10, "p"); g.signed(post, site)
        // M2: one Undo cancels both twins from the site, and counts as one decline.
        val del = { at: Long -> Unsigned(d.g, at, 5, listOf(listOf("e", post.id)), "") }
        val rs = java.util.Collections.synchronizedList(ArrayList<String?>())
        val ts = listOf(0L, 1L).map { k -> Thread { rs += g.gate(del(d.now + k), site, listOf("post")).error }.also { it.start() } }
        Thread.sleep(80); assertEquals(2, g.pendingUndos().size); assertTrue(g.undoPending(g.pendingUndos()[0].id)); ts.forEach { it.join() }
        assertEquals(listOf("declined: undone", "declined: undone"), rs.toList())
        // M3: nothing of the account's to delete.
        assertEquals("delete-none", g.judge(Unsigned(d.g, d.now, 5, listOf(listOf("a", "30023:${"cd".repeat(32)}:x")), ""), site, listOf("post")).row)
        // M5: a one-element e tag never breaks the bookkeeping.
        g.signed(signed(d, 5, listOf(listOf("e"), listOf("e", post.id)), d.now), site)
        assertEquals(1, d.meta.evidence().ledger.dels.size)
        // M1: a site's deletions are served one at a time, each counted from its judgement.
        val (gate, out) = g.serve(Unsigned(d.g, d.now, 5, listOf(listOf("e", post.id)), ""), site, listOf("post"), wait = false) { "signed" }
        assertEquals(null, out); assertEquals("undo", gate.verdict.level)
    }
}
