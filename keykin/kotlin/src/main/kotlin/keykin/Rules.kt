// The co-signer's history-free event rules (core §5.6, §5.7 item 4, §5.8) and RFC 8785 JCS.
package keykin

import org.json.JSONArray
import org.json.JSONObject

object Rules {
    fun replaceable(k: Int) = k == 0 || k == 3 || k in 10000..19999 || k in 30000..39999
    fun futureOk(kind: Int, ahead: Long) = !(replaceable(kind) || kind == 5) || ahead <= 600
    /** §5.8, exact as core 13.8: does this event need a lock approval or a passed hold? */
    fun destructive(kind: Int, content: String, tags: List<List<String>>, recentUnapproved: Int = 0): Boolean {
        if (kind == 62) return true
        if (kind in 1244..1247) return true   // Key families §4
        // A tag counts only with at least two elements, empty strings included.
        val counted = tags.filter { it.size >= 2 }
        if (kind == 5) { val n = deletionTargets(tags); return n >= 5 || recentUnapproved + n > 5 }
        if (kind == 0) {
            // §9.5 "Kind 0": the first five rules, numbers by grammar only; a field counts only with a
            // character outside the whitespace set.
            val o = try { Json.parse(content, grammar = true) as? JSONObject } catch (_: KeykinException) { null } ?: return true
            return listOf("name", "display_name", "about", "picture").none { val v = o.opt(it); v is String && v.any { c -> !jsSpace(c) } }
        }
        // Byte-exact and case-sensitive.
        if (kind == 10002 && counted.none { it[0] == "r" && (it[1].startsWith("wss://") || it[1].startsWith("ws://")) }) return true
        // "Empty content" is the zero-length string.
        if (kind == 3 || kind in 10000..10030 || kind in 30000..30030) return counted.all { it[0] == "d" } && content.isEmpty()
        return false
    }
    /** A deletion's targets: its distinct (`e` or `a`, value) pairs. */
    fun deletionTargets(tags: List<List<String>>) = tags.filter { it.size >= 2 && (it[0] == "e" || it[0] == "a") }.map { it[0] to it[1] }.toSet().size
    /** §9.5's whitespace set: U+0009–000D, U+0020, U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F,
     *  U+205F, U+3000, U+FEFF. */
    fun jsSpace(c: Char) = c in '\u0009'..'\u000d' || c in " \u00a0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff" || c in '\u2000'..'\u200a'
    private val lifetime = mapOf("sign" to 60L, "ask" to 120L, "member" to 7 * 86400L)
    private val allowed = mapOf("sign" to setOf("sign", "ask"), "commit" to setOf("sign", "ask"), "ecdh" to setOf("sign", "ask"),
        "challenge" to setOf("ask"), "hold" to setOf("member"), "release_request" to setOf("member"), "deliver" to setOf("member"))
    private val repeated = setOf("cancel", "withdraw", "upload", "upload_held", "push_register", "push_unregister", "notify_register", "paper_reissue",
        "helper_stop", "helper_resume", "account_delete", "deleted", "heir_request", "heir_remove",
        "delta", "paper_ck", "dk_seed", "release_seed", "paper_item", "welcome", "repair_sigma", "change", "ack")
    /** §5.6: null when fresh, else the refusal code. */
    fun lifetime(type: String, cls: String, age: Long): String? {
        // Core 13.12: types outside the table are `member` if a sender repeats them until answered, else `ask`.
        val ok = allowed[type] ?: if (type in repeated) setOf("member") else setOf("ask")
        if (cls !in lifetime || cls !in ok) return "bad_class"
        if (-age > 30) return "dated_ahead"
        if (age > lifetime[cls]!! + 30) return "expired"
        return null
    }
}

/** RFC 8785 over the complete tree (§9.5): keys sorted by UTF-16 code units (Kotlin's String order),
 *  strings as Json.str writes them, safe integers, depth at most 32; anything else is refused. */
object Jcs {
    fun of(v: Any?, depth: Int = 1): String {
        if (depth > Json.MAX_DEPTH) refuse("malformed", "JCS: nested deeper than ${Json.MAX_DEPTH}")
        return when (v) {
            null, JSONObject.NULL -> "null"
            is Boolean -> v.toString()
            is Int, is Long -> Json.num(v)
            is String -> Json.str(v)
            is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { of(v.get(it), depth + 1) }
            is JSONObject -> v.keySet().sorted().joinToString(",", "{", "}") { Json.str(it) + ":" + of(v.get(it), depth + 1) }
            else -> refuse("malformed", "JCS: ${v::class.simpleName}")
        }
    }
}
