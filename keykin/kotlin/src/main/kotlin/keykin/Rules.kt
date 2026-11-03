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
        if (kind == 5) { val n = tags.count { it[0] == "e" || it[0] == "a" }; return n >= 5 || recentUnapproved + n > 5 }
        if (kind == 0) {
            val o = try { JSONObject(content) } catch (_: Exception) { return true }
            if (hasDuplicateKey(content)) return true
            return listOf("name", "display_name", "about", "picture").none { val v = o.opt(it); v is String && v.isNotBlank() }
        }
        if (kind == 10002 && tags.none { it[0] == "r" && (it.getOrNull(1)?.let { u -> u.startsWith("wss://") || u.startsWith("ws://") } == true) }) return true
        if (kind == 3 || kind in 10000..10030 || kind in 30000..30030) return tags.all { it[0] == "d" } && content.isEmpty()
        return false
    }
    private fun hasDuplicateKey(text: String): Boolean {
        // org.json refuses duplicate keys on its own; anything it parsed has none.
        return try { JSONObject(text); false } catch (_: Exception) { true }
    }
    private val lifetime = mapOf("sign" to 60L, "ask" to 120L, "member" to 7 * 86400L)
    private val allowed = mapOf("sign" to setOf("sign", "ask"), "commit" to setOf("sign", "ask"), "ecdh" to setOf("sign", "ask"),
        "challenge" to setOf("ask"), "hold" to setOf("member"), "release_request" to setOf("member"), "deliver" to setOf("member"))
    private val repeated = setOf("cancel", "withdraw", "upload", "upload_held", "push_register", "push_unregister", "notify_register", "paper_reissue",
        "helper_stop", "helper_resume", "account_delete", "deleted", "heir_request", "heir_remove")
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

/** RFC 8785 for Keykin's bodies: strings, integers, booleans, null, arrays and objects. */
object Jcs {
    fun of(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is Boolean -> v.toString()
        is Number -> v.toLong().toString()
        is String -> JSONObject.quote(v).replace("\\/", "/")
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { of(v.get(it)) }
        is JSONObject -> v.keySet().sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + of(v.get(it)) }
        else -> error("JCS: ${v::class}")
    }
}
