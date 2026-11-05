// What a door may ask of the account (Doors §2, as device/doors.ts): a site over NIP-46, an app over NIP-55, or
// the app's own main process, which draws strangers' content, never gets the account's machinery signed (the
// signpost, keykin- data, epoch records, changes, key-family events). Sites and other apps never read what the
// account encrypted to itself (`mayDecrypt`). The app's own main process can, through keykin-android's
// `nip44Own`, as Cosign's does (private lists, NIP-78 app data), for the kinds the app declares it uses (`ownMay`):
// never a wallet's unless the app says so (review 15 M9).
package keykin

import org.json.JSONObject

object Doors {
    /** Doors 20 §2: the vaults spec's machinery (AUTH, CERT, KEYRING) and invitations (provisional numbers). */
    val VAULT_KINDS = setOf(4810, 4811, 30811)
    const val KIND_VAULT_INVITE = 4812
    private val VAULT_SECRETS = listOf("keys", "keys_ref", "secret", "inboxes", "genesis")
    /** The strict parser's reading; text it refuses that a site's lenient parser might still read (duplicate keys, say)
     *  counts as vault material when it names `vault` or kind 4812 at all, so nothing slips through on a parse gap. */
    private object Unreadable
    private fun parse(t: String): Any? = try { Json.parse(t) } catch (_: Exception) { if (t.contains("\"vault\"") || Regex("\"kind\"\\s*:\\s*4812\\b").containsMatchIn(t)) Unreadable else null }
    private fun vaultShape(x: Any?) = x is JSONObject && x.has("vault") && VAULT_SECRETS.any { x.has(it) }
    /** A vault payload itself (not a rumor): what a vault app's decrypt answers (Doors 20 §3.7). Strictly parsed only. */
    fun vaultPayload(text: String?): Boolean = text != null && (try { Json.parse(text) } catch (_: Exception) { null }).let { x ->
        // Never an event or rumor with vault fields added (review 22 L1): those go through the unwrap's signer check.
        vaultShape(x) && x is JSONObject && !x.has("kind") && !x.has("content") && !x.has("sig") }
    /** A plaintext no site may get or have encrypted: a kind-4812 rumor, or an object with `vault` and a secret field,
     *  at the top level or in a rumor's content (as TS `vaultPlaintext`). */
    fun vaultPlaintext(text: String?): Boolean {
        if (text == null) return false
        val x = parse(text)
        if (x === Unreadable || vaultShape(x)) return true
        if (x is JSONObject && (x.opt("kind") as? Number)?.toLong() != null && x.opt("content") is String) {
            if ((x.opt("kind") as Number).toLong() == KIND_VAULT_INVITE.toLong()) return true
            val inner = parse(x.getString("content")); if (inner === Unreadable || vaultShape(inner)) return true
        }
        return false
    }
    fun siteGuard(d: Device, kind: Int, tags: List<List<String>>) {
        if (kind == 30242 || kind == 24302) refuse("declined", "account machinery")
        // Doors 20 §2: vault machinery is the vault apps' own, never a site's; nor a deletion aimed at it by e, a or k.
        if (kind in VAULT_KINDS) refuse("declined", "vault machinery is never a site's to sign")
        if (kind == 5) for (t in tags) { if (t.size < 2) continue
            if (t[0] == "k" && t[1].toIntOrNull() in VAULT_KINDS) refuse("declined", "a deletion of vault machinery")
            if (t[0] == "a" && t[1].substringBefore(':').toIntOrNull() in VAULT_KINDS) refuse("declined", "a deletion of vault machinery")
            if (t[0] == "e" && d.history.get(t[1])?.kind in VAULT_KINDS) refuse("declined", "a deletion of vault machinery") }
        if (kind in 1244..1247) refuse("declined", "a key-family event is the person's own act, never a site's")
        val backups = listOfNotNull(d.view.backup)
        val signposts = backups.map { hex(sha(utf8("keykin-beacon/1"), unhex(it))) }.toSet()
        val dTag = tags.firstOrNull { it.size >= 2 && it[0] == "d" }?.get(1) ?: ""
        if (kind == 30078 && (dTag.lowercase() in signposts || dTag.startsWith("keykin-"))) refuse("declined", "the account's signpost and keykin- data are never a site's to write")
        if (kind == 5) for (t in tags) { val v = (t.getOrNull(1) ?: "").lowercase()
            if (t.getOrNull(0) == "a" && ((signposts.any { v.contains(it) } && v.contains(d.g)) || v.contains(":keykin-"))) refuse("declined", "a deletion of the account's signpost or keykin- data")
            // Nor by id: the grant events this device knows (their ended lists keep signed-out sites out, review 16 M3).
            if (t.getOrNull(0) == "e" && v in d.protectedIds) refuse("declined", "a deletion of the account's keykin- data") }
    }
    /** NIP-60's wallet kinds (wallet, token, spending history, the old wallet), and the default of what the app's
     *  own process may read of the account's to-self data: NIP-51 lists and sets and NIP-78 app data. */
    val WALLET_KINDS = setOf(17375, 7375, 7376, 37375)
    val DEFAULT_OWN_KINDS: Set<Int> = (10000..10102).toSet() + (30000..30030).toSet() + 30078
    /** Whether the app's own process may encrypt or decrypt to-self content of `kind` (`nip44Own`): only kinds the
     *  app declares it uses (`declared`, read in the signer process from the app's manifest; null: the default),
     *  and a wallet kind only when declared outright (the hub's guard on review 15 M9). */
    fun ownMay(kind: Int, declared: Set<Int>?): Boolean = if (declared != null) kind in declared else kind in DEFAULT_OWN_KINDS && kind !in WALLET_KINDS
    fun mayDecrypt(d: Device, peer: String) { if (peer.lowercase() == d.g) refuse("declined", "the account's own data is not a site's to read") }
}
