package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Recovery step 3: Kotlin's `recovery` approval signs what the TS reference's does (vectors/recovery-approval.json). */
class RecoveryApprovalTest {
    private val v = JSONObject(File(System.getProperty("keykin.recoveryapproval")).readText())
    @Test fun signsTheTsDigest() {
        val g = v.getString("g"); val Ksk = unhex("5e".repeat(32)); val K = Keykin.secp.pub(Ksk)
        for (k in 0 until v.getJSONArray("cases").length()) {
            val c = v.getJSONArray("cases").getJSONObject(k)
            val ph = Approvals.placeholder(c.getJSONArray("list"))
            assertEquals(c.getString("hash"), Approvals.hash(ph), "the placeholder list hashes as in TS")
            val a = Approve.recovery(g, ph, Ksk, JSONObject().put("r", "ab".repeat(16)), JSONArray()).getJSONObject("recovery")
            assertEquals(K, a.getString("backup"))
            assertTrue(schnorrVerify(a.getString("backup_sig"), unhex(c.getString("digest")), K), "signed over the TS digest")
        }
    }
}
