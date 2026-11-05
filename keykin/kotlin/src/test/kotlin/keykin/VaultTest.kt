package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** Doors 20 §3.7 in Kotlin: what a vault app's decrypt answers, and the derive formula against vaults.json (draft 7.13). */
class VaultTest {
    @Test fun payloadsOnlyNeverRumors() {
        val rumor = JSONObject().put("kind", 4812).put("pubkey", "ab".repeat(32)).put("created_at", 1).put("tags", JSONArray())
            .put("content", JSONObject().put("vault", "v").put("keys", JSONObject()).toString()).toString()
        val cases = listOf(
            JSONObject().put("vault", "v").put("keys", JSONObject()).toString() to true,
            JSONObject().put("vault", "v").put("secret", "x").toString() to true,
            JSONObject().put("vault", "v").put("name", "Notes").toString() to false,
            rumor to false, "a private message" to false, "{\"vault\":1,\"vault\":2,\"keys\":{}}" to false)
        for ((t, want) in cases) assertEquals(want, Doors.vaultPayload(t), t)
    }
    @Test fun deriveAsVaultsJson() {
        val f = File(System.getProperty("user.home"), "nostr-sync-nip/vectors/vaults.json"); if (!f.exists()) return
        val v = JSONObject(f.readText()); val dk = unhex(v.getJSONObject("inputs").getString("dk_S"))
        val info = { domain: String, hexBytes: String -> utf8(domain) + byteArrayOf(0) + unhex(hexBytes) }
        assertEquals(v.getJSONObject("owner_secret").getString("V"), hex(hkdf32(dk, info("nostr-vault/owner/1", v.getJSONObject("inputs").getString("vault_id")))))
        assertEquals(v.getJSONObject("keyring").getString("seal_key"), hex(hkdf32(dk, info("nostr-vault/keyring/1", v.getJSONObject("keyring").getString("d")))))
    }
}
