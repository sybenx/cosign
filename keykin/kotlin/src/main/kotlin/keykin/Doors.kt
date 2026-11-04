// What a door may ask of the account (Doors §2, as device/doors.ts): a site over NIP-46, an app over NIP-55, or
// the app's own main process, which draws strangers' content, never gets the account's machinery signed (the
// signpost, keykin- data, epoch records, changes, key-family events). Sites and other apps never read what the
// account encrypted to itself (`mayDecrypt`). The app's own main process can, through keykin-android's
// `nip44Own`, as Cosign's does (private lists, NIP-78 app data), for the kinds the app declares it uses (`ownMay`):
// never a wallet's unless the app says so (review 15 M9).
package keykin

object Doors {
    fun siteGuard(d: Device, kind: Int, tags: List<List<String>>) {
        if (kind == 30242 || kind == 24302) refuse("declined", "account machinery")
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
