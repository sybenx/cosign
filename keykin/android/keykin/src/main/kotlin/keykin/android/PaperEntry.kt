// The paper's approval on Android (core §6.2 `paper`): the person types the paper's 24 words on an activity the
// app runs in the signer process, never in the main process, which draws strangers' content and never holds key
// material. The words become the backup secret here, approve the list with this device and a server's challenge
// bound to the backup key, and are destroyed at once.
package keykin.android

import keykin.Backup
import keykin.KeykinException
import org.json.JSONArray
import org.json.JSONObject

object PaperEntry {
    /** Approve `list` in `slot` with the paper whose 24 words the person typed, and submit it. Refuses words that
     *  aren't a Keykin paper ("bad_backup"), a wallet seed ("wallet_seed"), or another paper ("not_current_backup"). */
    fun submit(slot: String, list: JSONArray, words: List<String>): List<JSONObject> {
        Proc.signerOnly("PaperEntry")
        val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
        val sk = Backup.readBackupWords(words)
        try { return d.submit(list, d.approveWithPaper(list, sk)) } finally { sk.fill(0) }
    }
    /** The paper check (Backup): whether the 24 words the person typed are this account's current paper. The words
     *  are read and destroyed here, in the signer process, and never submit anything. */
    fun check(slot: String, words: List<String>): Boolean {
        Proc.signerOnly("PaperEntry")
        val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
        val sk = try { Backup.readBackupWords(words) } catch (_: KeykinException) { return false }
        try { return keykin.Keykin.secp.pub(sk) == d.view.backup } finally { sk.fill(0) }
    }
    /** The list for removing a lost device (core §6.7.6 F2): the remove and its redeal, dealt by this one. */
    fun removeList(slot: String, key: String): JSONArray {
        val d = Memberships.signer(slot).device ?: throw KeykinException("no_membership")
        return JSONArray().put(JSONObject().put("remove", key)).put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub)))
    }
}
