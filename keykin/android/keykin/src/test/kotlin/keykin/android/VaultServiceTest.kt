package keykin.android

import keykin.KeykinException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** The vault door's app ids and answers (Doors 20 §3.7). */
class VaultServiceTest {
    @Test fun appIdNamesPackageAndCertificate() {
        val a = VaultService.appId("org.example.notes", byteArrayOf(1, 2, 3))
        assertEquals(true, a.startsWith("org.example.notes@")); assertEquals(32, a.substringAfter('@').length)
        assertNotEquals(a, VaultService.appId("org.example.notes", byteArrayOf(1, 2, 4)))
    }
    @Test fun answersCarryResultOrCodeNeverATrace() {
        assertEquals("x", JSONObject(VaultService.answer { "x" }).getString("result"))
        assertEquals("declined: not a vault payload", JSONObject(VaultService.answer { throw KeykinException("declined", "not a vault payload") }).getString("error"))
        assertEquals("internal: the call failed", JSONObject(VaultService.answer { throw IllegalStateException("secret detail") }).getString("error"))
    }
}
