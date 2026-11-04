// The JSON profile (core §9.5): RFC 8259 exactly, no key twice, integers spelled -?(0|[1-9][0-9]*) up to
// 2^53 − 1, no lone surrogates or control characters but five (after escapes are undone), depth 32.
// Parses into org.json values so the rest of the port can navigate them; writes by hand, never through
// org.json (it writes `/` as `\/`).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

object Json {
    const val MAX_DEPTH = 32
    private const val SAFE = 9007199254740991L

    /** `grammar` is kind 0 content's reading: numbers are checked against the grammar only, never converted. */
    fun parse(text: String, grammar: Boolean = false): Any? { val p = P(text, grammar); p.ws(); val v = p.value(1); p.ws(); if (p.i != text.length) refuse("malformed", "text after the value"); return v }
    fun obj(text: String): JSONObject = parse(text) as? JSONObject ?: refuse("malformed", "not an object")

    /** Fatal UTF-8: overlong forms, encoded surrogates and values past U+10FFFF are refused; a BOM is kept,
     *  so the reader refuses it. */
    fun utf8Strict(b: ByteArray): String = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
    } catch (_: CharacterCodingException) { refuse("malformed", "invalid UTF-8") }

    /** Why a string breaks §9.5, or null. */
    fun fault(s: String): String? {
        var k = 0
        while (k < s.length) {
            val c = s[k]
            if (c < ' ' && c != '\b' && c != '\t' && c != '\n' && c != '\u000c' && c != '\r') return "contains control character U+%04X".format(c.code)
            if (Character.isHighSurrogate(c)) { if (k + 1 < s.length && Character.isLowSurrogate(s[k + 1])) { k += 2; continue }; return "contains a lone surrogate" }
            if (Character.isLowSurrogate(c)) return "contains a lone surrogate"
            k++
        }
        return null
    }

    private class P(val s: String, val grammar: Boolean) {
        var i = 0
        fun ws() { while (i < s.length && s[i] in " \t\n\r") i++ }
        fun value(depth: Int): Any {
            if (depth > MAX_DEPTH) refuse("malformed", "nested deeper than $MAX_DEPTH")
            if (i >= s.length) refuse("malformed", "unexpected end")
            return when (s[i]) {
                '{' -> { i++; ws(); val o = JSONObject(); val seen = HashSet<String>()
                    if (s.getOrNull(i) == '}') { i++; return o }
                    while (true) {
                        if (s.getOrNull(i) != '"') refuse("malformed", "a key")
                        val k = str(); if (!seen.add(k)) refuse("malformed", "the key \"$k\" twice")
                        ws(); if (s.getOrNull(i) != ':') refuse("malformed", "\":\""); i++; ws(); o.put(k, value(depth + 1)); ws()
                        when (s.getOrNull(i)) { ',' -> { i++; ws() }; '}' -> { i++; return o }; else -> refuse("malformed", "\",\" or \"}\"") }
                    }
                    @Suppress("UNREACHABLE_CODE") o }
                '[' -> { i++; ws(); val a = JSONArray()
                    if (s.getOrNull(i) == ']') { i++; return a }
                    while (true) { a.put(value(depth + 1)); ws()
                        when (s.getOrNull(i)) { ',' -> { i++; ws() }; ']' -> { i++; return a }; else -> refuse("malformed", "\",\" or \"]\"") } }
                    @Suppress("UNREACHABLE_CODE") a }
                '"' -> str()
                't' -> lit("true", true); 'f' -> lit("false", false); 'n' -> lit("null", JSONObject.NULL)
                else -> num()
            }
        }
        fun lit(w: String, v: Any): Any { if (!s.startsWith(w, i)) refuse("malformed", "literal"); i += w.length; return v }
        fun num(): Any {
            val m = NUM.matchAt(s, i) ?: refuse("malformed", "unexpected \"${s[i]}\"")
            i += m.value.length
            // Kind 0 content: the grammar only; the text itself stands in for the number.
            if (grammar) return Grammar(m.value)
            if (m.groups[2] != null || m.groups[3] != null) refuse("malformed", "the number ${m.value} is not an integer spelled -?(0|[1-9][0-9]*)")
            if (m.value == "-0") refuse("malformed", "-0")
            val n = m.value.toBigInteger()
            if (n.abs() > SAFE.toBigInteger()) refuse("malformed", "the number ${m.value} is beyond 2^53 - 1")
            return n.toLong()
        }
        fun str(): String {
            i++; val b = StringBuilder()
            while (true) {
                if (i >= s.length) refuse("malformed", "a string")
                val c = s[i++]
                when {
                    c == '"' -> { val v = b.toString(); fault(v)?.let { refuse("malformed", it) }; return v }
                    c == '\\' -> { val e = s.getOrNull(i++) ?: refuse("malformed", "a string")
                        when (e) { '"' -> b.append('"'); '\\' -> b.append('\\'); '/' -> b.append('/'); 'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                            'n' -> b.append('\n'); 'r' -> b.append('\r'); 't' -> b.append('\t')
                            'u' -> { val h = s.substring(i, minOf(i + 4, s.length)); if (!HEX4.matches(h)) refuse("malformed", "a string"); b.append(h.toInt(16).toChar()); i += 4 }
                            else -> refuse("malformed", "a string") } }
                    c < ' ' -> refuse("malformed", "a string")
                    else -> b.append(c)
                }
            }
        }
    }
    private val NUM = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")
    private val HEX4 = Regex("[0-9a-fA-F]{4}")
    /** A number in kind 0 content, kept as its text. */
    data class Grammar(val text: String)

    /** A string as NIP-01 ids and JCS write it (§9.5): `"` and `\` escaped, the five as \b \t \n \f \r,
     *  everything else raw. What the profile refuses is refused here too, never escaped. */
    fun str(v: String): String {
        fault(v)?.let { refuse("malformed", it) }
        return buildString {
            append('"')
            for (ch in v) when (ch) {
                '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t")
                '\b' -> append("\\b"); '\u000c' -> append("\\f"); else -> append(ch)
            }
            append('"')
        }
    }
    /** A safe integer; anything else is refused in a Keykin body. */
    fun num(v: Any): String {
        val n: Long = when (v) { is Int -> v.toLong(); is Long -> v; else -> refuse("malformed", "numbers are safe integers") }
        if (Math.abs(n) > SAFE) refuse("malformed", "numbers are safe integers")
        return n.toString()
    }
    fun isInt(v: Any?) = intOrNull(v) != null
    fun long(v: Any?): Long = intOrNull(v) ?: refuse("malformed", "not an integer")
    private fun intOrNull(v: Any?): Long? = when (v) { is Int -> v.toLong(); is Long -> v.takeIf { Math.abs(it) <= SAFE }; else -> null }
}
