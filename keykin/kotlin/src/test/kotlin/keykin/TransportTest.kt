package keykin

import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The Kotlin envelope (core §9.1). The differential probes (vectors/diff) check it byte for byte
 *  against the TS reference and nostr-tools; these keep it covered by `gradlew test`. */
class TransportTest {
    private val rnd = java.security.SecureRandom()
    private fun bytes(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    @Test fun chacha20MatchesTheJdk() {
        for (len in listOf(1, 63, 64, 65, 200, 4096)) for (ctr in listOf(0, 1, 7)) {
            val key = bytes(32); val nonce = bytes(12); val data = bytes(len)
            val jdk = Cipher.getInstance("ChaCha20").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), ChaCha20ParameterSpec(nonce, ctr)) }.doFinal(data)
            assertContentEquals(jdk, ChaCha20.xor(key, nonce, data, ctr), "len $len counter $ctr")
        }
    }

    @Test fun bip340SignaturesVerify() {
        repeat(5) {
            val sk = bytes(32).also { it[0] = 0x22 }; val msg = bytes(32)
            val sig = Secp.Reference.schnorrSign(msg, sk, bytes(32))
            assertTrue(schnorrVerify(sig, msg, Secp.Reference.pub(sk)))
        }
    }

    @Test fun wrapAndUnwrap() {
        val env = Envelope()
        val a = bytes(32).also { it[0] = 0x11 }; val b = bytes(32).also { it[0] = 0x12 }; val c = bytes(32).also { it[0] = 0x13 }
        val body = JSONObject().put("v", 1).put("type", "state_get").put("id", "ab".repeat(16)).put("note", "é 😀")
        val w = env.wrap(a, Secp.Reference.pub(b), body, 1_800_000_000)
        val o = env.unwrap(b, w)
        assertEquals(Secp.Reference.pub(a), o.from)
        assertEquals(Jcs.of(body), Jcs.of(o.body))
        assertEquals("undecryptable", assertFailsWith<KeykinException> { env.unwrap(c, w) }.code, "another key")
        assertEquals("bad_wrap", assertFailsWith<KeykinException> { env.unwrap(b, JSONObject(w.toString()).put("content", w.getString("content").dropLast(8) + "AAAAAAA=")) }.code)
        assertEquals("not_a_wrap", assertFailsWith<KeykinException> { env.unwrap(b, JSONObject(w.toString()).put("kind", 1)) }.code)
    }
}
