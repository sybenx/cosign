package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** vectors/membersig.json, made by the TS reference: the same digests, the same signatures (zero aux),
 *  the same refused domains. */
class MemberSigTest {
    private val v = JSONObject(File(System.getProperty("keykin.membersig")).readText())
    @Test fun vectors() {
        val sk = unhex(v.getString("member_sk")); val key = v.getString("member_key")
        assertEquals(key, Secp.Reference.pub(sk))
        val valid = v.getJSONArray("valid")
        for (k in 0 until valid.length()) {
            val x = valid.getJSONObject(k); val msg = unhex(x.getString("message"))
            assertEquals(x.getString("digest"), hex(MemberSig.digest(x.getString("domain"), msg)))
            assertEquals(x.getString("sig"), MemberSig.sign(Secp.Reference, sk, x.getString("domain"), msg, ByteArray(32)))
            assertTrue(MemberSig.verify(x.getString("sig"), x.getString("domain"), msg, key))
            assertFalse(MemberSig.verify(x.getString("sig"), x.getString("domain"), msg + byteArrayOf(1), key))
        }
        val refused = v.getJSONArray("refused_domains")
        for (k in 0 until refused.length()) {
            val d = refused.getJSONObject(k).getString("domain")
            assertNotNull(MemberSig.fault(d), d)
            assertFailsWith<KeykinException>(d) { MemberSig.register(d) }
        }
        assertFailsWith<KeykinException> { MemberSig.digest("nostr-vault/unregistered/1", ByteArray(0)) }
    }
}
