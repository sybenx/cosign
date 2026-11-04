package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** vectors/push.json, made by the TS reference: Kotlin decrypts the server's push and checks its payload. */
class PushTest {
    private val v = JSONObject(File(System.getProperty("keykin.push")).readText())
    @Test fun decryptsAndChecksWhatATsServerSent() {
        val sk = unhex(v.getString("ua_sk")); val auth = unhex(v.getString("auth"))
        assertEquals(v.getString("p256dh"), b64u(Push.pubFor(sk)))
        val plain = Push.decrypt(unhex(v.getString("body")), sk, auth)
        assertEquals(v.getString("plain"), hex(plain))
        val p = Push.read(plain, setOf(v.getString("host_key")))
        assertEquals("ask", p.getString("cls"))
        assertFailsWith<KeykinException> { Push.read(plain, setOf("ab".repeat(32))) }
        val bad = v.getJSONArray("refused")
        for (k in 0 until bad.length()) assertFailsWith<KeykinException> { Push.decrypt(unhex(bad.getString(k)), sk, auth) }
    }
    @Test fun aFreshKeyIsItsOwnPub() {
        val (sk, pub) = Push.newKey()
        assertTrue(Push.pubFor(sk).contentEquals(pub))
    }
}
