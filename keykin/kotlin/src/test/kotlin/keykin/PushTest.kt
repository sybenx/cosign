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

/** UnifiedPush connector 3.x decrypts Web Push with its own keys: an address registered with them takes only the
 *  connector's plaintext, and that still only under a seated server's host signature. */
class ConnectorPushTest {
    private val v = JSONObject(File(System.getProperty("keykin.push")).readText())
    private val g = JSONObject(File(System.getProperty("keykin.grants")).readText())
    private fun device() = Device.fromSnapshot(g.getString("before"), RelayNet(emptyList()))
    @Test fun aConnectorAddressTakesOnlyCheckedPlaintext() {
        val d = device()
        val url = "https://push.test/up/a"; val own = "https://push.test/up/b"
        synchronized(d) {
            d.pushKeys[url] = JSONObject().put("connector", true).put("cls", "ask")
            val (sk, _) = Push.newKey()
            d.pushKeys[own] = JSONObject().put("sk", hex(sk)).put("auth", v.getString("auth")).put("cls", "ask")
        }
        val plain = Push.decrypt(unhex(v.getString("body")), unhex(v.getString("ua_sk")), unhex(v.getString("auth")))
        // Signed by a host that isn't one of this account's seated servers: refused, plaintext or not.
        assertEquals(null, d.onPushDecrypted(url, plain))
        // Not JSON, or not signed: refused without an exception.
        assertEquals(null, d.onPushDecrypted(url, "not json".toByteArray()))
        assertEquals(null, d.onPushDecrypted(url, JSONObject().put("srv", "ab".repeat(32)).toString().toByteArray()))
        // The raw path never reads a connector address, and the plaintext path never reads an own-keys address.
        assertEquals(null, d.onPush(url, unhex(v.getString("body"))))
        assertEquals(null, d.onPushDecrypted(own, plain))
        assertEquals(null, d.onPushDecrypted("https://push.test/unknown", plain))
    }
}
