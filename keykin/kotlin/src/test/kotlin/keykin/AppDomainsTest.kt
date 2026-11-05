package keykin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Core 14.25 §4.5's vectors (docs/keykin/vectors/vectors.json `app_private`, spec 2c44a59). */
class AppDomainsTest {
    private val dk = unhex("c4af916220bd2a612e1536730b177fa36193468ad5e7f79dbed885c81fb0cdcf")
    private val android = "android:org.example.notes:" + "ab".repeat(32)
    private val apple = "apple:ABCDE12345:org.example.notes"
    private val dA = "id-7e1b64d5dd15b89b9946ba796d0de2fad0f1caabb15cfa391e32c21a1b2a0f6d/notes/1"
    private val dB = "id-2c853c163251a3d00879f9f354eadc57dab51c57818ea72db9c85a9c460c206c/notes/1"

    @Test fun identityDomains() {
        assertEquals(dA, AppDomains.own(android, "notes/1"))
        assertEquals(dB, AppDomains.own(apple, "notes/1"))
        assertEquals(android, AppDomains.androidIdentity("org.example.notes", "ab".repeat(32)))
    }
    @Test fun derive() {
        val bytes = unhex("7265636f72642d31")
        assertEquals("1679174ab374b5377e669c38eab511889c4c3af318ffff5b693a28d6cbccfb2f", hex(AppDomains.derive(dk, dA, bytes)))
        assertEquals("d8630e5941ca004ccb980791eece21e11005b4c6b4bea8ce2acab59b6874cee7", hex(AppDomains.derive(dk, dB, bytes)))
        assertEquals("23ade44086eaeb34ef57ce995c379bdd5fb97380db13863ade4548b1d1d70e5a", hex(AppDomains.derive(dk, "nostr-vault/owner/1", bytes)))
    }
    @Test fun refused() {
        fun code(f: () -> Unit) = assertFailsWith<KeykinException> { f() }.code
        assertEquals("bad_domain", code { AppDomains.check(android, dA.replaceFirst("/", "x/")) })   // malformed identity domain
        assertEquals("bad_domain", code { AppDomains.check(apple, dA) })                             // another app's
        assertEquals("bad_domain", code { AppDomains.check("ext:chrome:" + "abcdefghijklmnop".repeat(2), dA) })
        AppDomains.check("ext:chrome:" + "abcdefghijklmnop".repeat(2), "notes.example/data/1")         // open: fine
        assertEquals("bad_domain", code { AppDomains.check("linux:/usr/bin/notes", dA) })
        AppDomains.check(android, dA)
        assertEquals("bad_domain", code { AppDomains.own(android, "Marble/Devices") })               // no version, capitals
        assertEquals("bad_caller", code { AppDomains.androidIdentity("org.example.notes", "AB".repeat(32)) })
    }

    @Test fun ownKeyOnADevice() {
        val v = org.json.JSONObject(java.io.File(System.getProperty("keykin.grants")).readText())
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val (st, k) = d.ownKey(android, "notes/1")
        assertEquals(d.currentState().second, st)
        assertEquals(hex(k), hex(d.ownKey(android, "notes/1", st).second), "the same key for the state named")
        assertEquals(hex(AppDomains.derive(d.dataKey().second, dA, ByteArray(0))), hex(k))
        kotlin.test.assertNotEquals(hex(k), hex(d.ownKey(apple, "notes/1").second), "another app, another key")
        kotlin.test.assertNotEquals(hex(k), hex(d.ownKey(android, "notes/2").second), "another label, another key")
        assertEquals("state_gone", assertFailsWith<KeykinException> { d.ownKey(android, "notes/1", "00".repeat(32)) }.code)
        assertEquals("bad_domain", assertFailsWith<KeykinException> { d.ownKey(android, "notes") }.code)
    }
}
