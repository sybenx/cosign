package cc.aaro.cosign.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Writes JSON exactly as JavaScript's JSON.stringify does, which is what NIP-01's event
 * id is computed over: only `"`, `\`, and control characters are escaped, and those
 * with the short forms where JSON has them.
 */
object Json {
    fun quote(s: String, out: StringBuilder) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c == '\b' -> out.append("\\b")
                c == '\u000c' -> out.append("\\f")
                c.code < 0x20 -> out.append("\\u").append(String.format("%04x", c.code))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    out.append(c).append(s[i + 1]); i++
                }
                Character.isSurrogate(c) -> out.append("\\u").append(String.format("%04x", c.code))
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }

    fun write(value: Any?, out: StringBuilder) {
        when (value) {
            null -> out.append("null")
            is String -> quote(value, out)
            is Boolean -> out.append(value.toString())
            is Int, is Long -> out.append(value.toString())
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { i, v -> if (i > 0) out.append(','); write(v, out) }
                out.append(']')
            }
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) out.append(',')
                    first = false
                    quote(k as String, out)
                    out.append(':')
                    write(v, out)
                }
                out.append('}')
            }
            else -> throw IllegalArgumentException("json: cannot write ${value::class}")
        }
    }

    fun stringify(value: Any?): String = StringBuilder().also { write(value, it) }.toString()

    /** Parses into plain Kotlin values: Map, List, String, Long, Double, Boolean, null. Null on malformed input. */
    fun parse(text: String): Any? = try {
        when (text.trimStart().firstOrNull()) {
            '{' -> plain(JSONObject(text))
            '[' -> plain(JSONArray(text))
            else -> null
        }
    } catch (_: Exception) {
        null
    }

    private fun plain(v: Any?): Any? = when (v) {
        is JSONObject -> v.keys().asSequence().associateWith { plain(v.get(it)) }
        is JSONArray -> (0 until v.length()).map { plain(v.get(it)) }
        JSONObject.NULL -> null
        is Int -> v.toLong()
        is Long -> v
        is Number -> v.toDouble()
        else -> v
    }
}
