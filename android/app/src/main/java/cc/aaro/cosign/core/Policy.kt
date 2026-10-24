package cc.aaro.cosign.core

/**
 * What has to wait for you: the phone's own copy of server/policy.ts, line for line.
 *
 * The phone co-signs routine things without asking, so it can't take a server's word
 * that something is routine: a compromised server could just leave the flag off. It
 * judges each event itself, against the last version of that list it has seen signed.
 */
object Policy {
    val ARCHIVED = setOf(
        0, 3, 10000, 10001, 10002, 10003, 10004, 10006, 10007, 10015, 10030,
        30000, 30001, 30002, 30003, 30004, 30015, 30030,
    )

    private val NAMES = mapOf(
        0 to ("profile" to "profile field"), 3 to ("follow list" to "follow"), 10000 to ("mute list" to "mute"), 10001 to ("pinned notes" to "pin"),
        10002 to ("relay list" to "relay"), 10003 to ("bookmarks" to "bookmark"), 10004 to ("communities" to "community"),
        10006 to ("blocked relays" to "relay"), 10007 to ("search relays" to "relay"), 10015 to ("interests" to "interest"), 10030 to ("emoji list" to "emoji"),
        30000 to ("follow set" to "person"), 30001 to ("list" to "item"), 30002 to ("relay set" to "relay"), 30003 to ("bookmark set" to "bookmark"),
        30004 to ("curation set" to "item"), 30015 to ("interest set" to "interest"), 30030 to ("emoji set" to "emoji"),
    )
    private val RELAYISH = setOf(10002, 10006, 10007, 30002)
    private val PROFILE_FIELDS = listOf("name", "display_name", "picture", "about", "nip05", "lud16", "banner", "website")

    private fun kindName(k: Int) = NAMES[k]?.first ?: "kind $k event"
    private fun itemName(k: Int) = NAMES[k]?.second ?: "item"
    private fun plural(n: Int, k: Int) = "$n ${itemName(k)}${if (n == 1) "" else "s"}"

    /** Replaceable events are keyed by kind; parameterised ones by kind and d tag. */
    fun keyOf(e: Event): String = if (e.kind in 30000 until 40000) "${e.kind}:${e.firstTag("d") ?: ""}" else "${e.kind}"

    private fun items(e: Event): List<String> = when (e.kind) {
        3 -> e.tags.filter { it.size > 1 && it[0] == "p" }.map { it[1] }
        in RELAYISH -> e.tags.filter { it.size > 1 && (it[0] == "r" || it[0] == "relay") }.map { it[1].trimEnd('/') }
        else -> e.tags.filter { it.isNotEmpty() && it[0] != "d" && it[0] != "title" && it[0] != "description" }.map { Json.stringify(it.take(2)) }
    }

    private fun profile(e: Event?): Map<*, *> = try { Json.parse(e?.content ?: "{}") as? Map<*, *> ?: emptyMap<String, Any>() } catch (_: Exception) { emptyMap<String, Any>() }
    private fun filled(v: Any?) = if (v is String) v.isNotBlank() else v != null

    /** Set when you have to approve: what would be destroyed, in plain words. */
    fun hold(e: Event, prev: Event?): String? {
        if (e.kind == 62) return "Ask relays to erase everything you have ever published"
        if (e.kind == 5) {
            val targets = e.tags.count { it.isNotEmpty() && (it[0] == "e" || it[0] == "a") }
            val core = e.tags.filter { it.size > 1 && (it[0] == "a" || it[0] == "k") }.mapNotNull { it[1].substringBefore(':').toIntOrNull() }.filter { it in ARCHIVED }
            if (core.isNotEmpty()) return "Delete your ${kindName(core[0])}"
            if (targets >= 5) return "Delete $targets of your events"
            return null
        }
        if (e.kind !in ARCHIVED || prev == null) return null
        if (e.kind == 0) {
            val was = profile(prev); val now = profile(e)
            val wiped = PROFILE_FIELDS.filter { filled(was[it]) && !filled(now[it]) }
            return if (wiped.size >= 2 || (now.isEmpty() && was.isNotEmpty())) "Wipe your profile: ${wiped.joinToString(", ").ifEmpty { "everything" }}" else null
        }
        val before = items(prev); val after = items(e)
        val kept = after.toSet(); val had = before.toSet()
        val removed = before.count { it !in kept }
        val added = after.count { it !in had }
        if (after.isEmpty() && before.size >= 3) return "Empty your ${kindName(e.kind)} (it has ${plural(before.size, e.kind)})"
        val big = if (e.kind in RELAYISH) removed >= 2 && removed >= before.size * 0.5 else removed >= 10 && removed >= before.size * 0.2
        return if (big) "Remove $removed of your ${before.size} ${itemName(e.kind)}s" + (if (added > 0) " (and add $added)" else "") else null
    }
}
