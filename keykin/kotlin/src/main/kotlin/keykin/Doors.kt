// What a door may ask of the account (Doors §2, as device/doors.ts): a site over NIP-46, an app over NIP-55, or
// the app's own main process, which draws strangers' content, never gets the account's machinery signed (the
// signpost, keykin- data, epoch records, changes, key-family events). Sites and other apps never read what the
// account encrypted to itself (`mayDecrypt`). The app's own main process can, through keykin-android's
// `nip44Own`, as Cosign's does for its NIP-78 app data: that is the app's choice to make (review 15 M9).
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
            if (t.getOrNull(0) == "a" && ((signposts.any { v.contains(it) } && v.contains(d.g)) || v.contains(":keykin-"))) refuse("declined", "a deletion of the account's signpost or keykin- data") }
    }
    fun mayDecrypt(d: Device, peer: String) { if (peer.lowercase() == d.g) refuse("declined", "the account's own data is not a site's to read") }
}
