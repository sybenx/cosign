// The strict JSON profile (spec issue 45): RFC 8259 exactly, an object never names a key twice, and
// strings and numbers serialised as JavaScript's JSON.stringify writes them (RFC 8785 for strings).
// Parses into org.json values so the rest of the port can navigate them.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigDecimal

object Json {
    fun parse(text: String): Any? { val p = P(text); p.ws(); val v = p.value(); p.ws(); if (p.i != text.length) refuse("malformed", "trailing text"); return v }
    fun obj(text: String): JSONObject = parse(text) as? JSONObject ?: refuse("malformed", "not an object")

    private class P(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i] in " \t\n\r") i++ }
        fun value(): Any? {
            if (i >= s.length) refuse("malformed", "end")
            return when (s[i]) {
                '{' -> { i++; val o = JSONObject(); val seen = HashSet<String>(); ws()
                    if (s.getOrNull(i) == '}') { i++; return o }
                    while (true) { ws(); if (s.getOrNull(i) != '"') refuse("malformed", "key"); val k = str(); if (!seen.add(k)) refuse("malformed", "duplicate key")
                        ws(); if (s.getOrNull(i) != ':') refuse("malformed", ":"); i++; ws(); o.put(k, value() ?: JSONObject.NULL); ws()
                        when (s.getOrNull(i)) { ',' -> i++; '}' -> { i++; return o }; else -> refuse("malformed", ",") } } ; @Suppress("UNREACHABLE_CODE") o }
                '[' -> { i++; val a = JSONArray(); ws()
                    if (s.getOrNull(i) == ']') { i++; return a }
                    while (true) { ws(); a.put(value() ?: JSONObject.NULL); ws()
                        when (s.getOrNull(i)) { ',' -> i++; ']' -> { i++; return a }; else -> refuse("malformed", ",") } } ; @Suppress("UNREACHABLE_CODE") a }
                '"' -> str()
                't' -> lit("true", true); 'f' -> lit("false", false); 'n' -> lit("null", JSONObject.NULL)
                else -> num()
            }
        }
        fun lit(w: String, v: Any): Any { if (!s.startsWith(w, i)) refuse("malformed", "literal"); i += w.length; return v }
        fun num(): Any {
            val m = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?").matchAt(s, i) ?: refuse("malformed", "number")
            i += m.value.length
            val d = BigDecimal(m.value)
            // An integral value is an integer, however it is written (1.0 is 1), as JavaScript sees it.
            return try { d.toBigIntegerExact().let { if (it.bitLength() < 63) it.toLong() else d } } catch (_: ArithmeticException) { d }
        }
        fun str(): String {
            i++; val b = StringBuilder()
            while (true) {
                if (i >= s.length) refuse("malformed", "string")
                val c = s[i++]
                when {
                    c == '"' -> return b.toString()
                    c == '\\' -> { val e = s.getOrNull(i++) ?: refuse("malformed", "escape")
                        when (e) { '"' -> b.append('"'); '\\' -> b.append('\\'); '/' -> b.append('/'); 'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                            'n' -> b.append('\n'); 'r' -> b.append('\r'); 't' -> b.append('\t')
                            'u' -> { val h = s.substring(i, minOf(i + 4, s.length)); if (!Regex("[0-9a-fA-F]{4}").matches(h)) refuse("malformed", "\\u"); b.append(h.toInt(16).toChar()); i += 4 }
                            else -> refuse("malformed", "escape") } }
                    c < ' ' -> refuse("malformed", "control character in a string")
                    else -> b.append(c)
                }
            }
        }
    }

    /** A string as JSON.stringify writes it: `"` and `\` escaped, control characters as \b \f \n \r \t
     *  or \u00xx, lone surrogates as \udxxx, everything else raw. */
    fun str(v: String): String = buildString {
        append('"')
        var k = 0
        while (k < v.length) {
            val ch = v[k]
            when {
                ch == '"' -> append("\\\""); ch == '\\' -> append("\\\\")
                ch == '\n' -> append("\\n"); ch == '\r' -> append("\\r"); ch == '\t' -> append("\\t")
                ch == '\b' -> append("\\b"); ch == '\u000c' -> append("\\f")
                ch < ' ' -> append("\\u%04x".format(ch.code))
                Character.isHighSurrogate(ch) && k + 1 < v.length && Character.isLowSurrogate(v[k + 1]) -> { append(ch); append(v[k + 1]); k++ }
                Character.isSurrogate(ch) -> append("\\u%04x".format(ch.code))
                else -> append(ch)
            }
            k++
        }
        append('"')
    }
    /** An integer as JSON.stringify writes a safe integer; anything else is refused in a Keykin body. */
    private const val SAFE = 9007199254740991L
    fun num(v: Any): String {
        val n: Long = when (v) {
            is Int -> v.toLong(); is Long -> v
            is Double -> if (v == Math.rint(v) && Math.abs(v) <= SAFE) v.toLong() else refuse("malformed", "numbers are safe integers")
            is BigDecimal -> try { v.toBigIntegerExact().longValueExact() } catch (_: ArithmeticException) { refuse("malformed", "numbers are safe integers") }
            else -> refuse("malformed", "number")
        }
        if (Math.abs(n) > SAFE) refuse("malformed", "numbers are safe integers")
        return n.toString()
    }
    /** An integer as JavaScript sees one: 1.0 is 1. Only safe integers count. */
    fun isInt(v: Any?) = intOrNull(v) != null
    fun long(v: Any?): Long = intOrNull(v) ?: refuse("malformed", "not an integer")
    private fun intOrNull(v: Any?): Long? = when (v) {
        is Int -> v.toLong(); is Long -> v.takeIf { Math.abs(it) <= SAFE }
        is Double -> v.takeIf { it == Math.rint(it) && Math.abs(it) <= SAFE }?.toLong()
        is BigDecimal -> try { v.toBigIntegerExact().longValueExact().takeIf { Math.abs(it) <= SAFE } } catch (_: ArithmeticException) { null }
        else -> null
    }
}
