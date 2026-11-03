package keykin

import org.json.JSONArray
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Slip39Test {
    @Test fun wordlist() { assertEquals(1024, Slip39.words.size); assertEquals("bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3", hex(sha(utf8(Slip39.words.joinToString("\n") + "\n")))) }
    @Test fun officialVectors() {
        val v = JSONArray(File(System.getProperty("keykin.slip39vectors")).readText())
        for (k in 0 until v.length()) {
            val c = v.getJSONArray(k); val ms = (0 until c.getJSONArray(1).length()).map { c.getJSONArray(1).getString(it) }
            val want = c.getString(2)
            if (want.isNotEmpty()) assertEquals(want, hex(Slip39.combine(ms, "TREZOR")), c.getString(0))
            else assertFailsWith<KeykinException>(c.getString(0)) { Slip39.combine(ms, "TREZOR") }
        }
    }
    @Test fun backupPieces() {
        val secret = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val p = Slip39.generate(1, listOf(2 to 3), secret)[0]
        for ((a, b) in listOf(0 to 1, 0 to 2, 1 to 2)) assertEquals(hex(secret), hex(Slip39.combine(listOf(p[a], p[b]))))
        assertFailsWith<KeykinException> { Slip39.combine(listOf(p[0])) }
        for (s in p) assertEquals(s, Slip39.encode(Slip39.decode(s)))
    }
    @Test fun review7() {
        val secret = ByteArray(32) { it.toByte() }
        val p = Slip39.generate(1, listOf(2 to 3), secret)[0]
        assertEquals(hex(secret), hex(Slip39.combine(listOf(" \t" + p[0].replace(" ", "\r\n") + "\n", p[1]))))
        for (sep in listOf("\u00a0", "\u2003", "\u3000", "\u2028", "\ufeff", "\u001c")) assertFailsWith<KeykinException> { Slip39.combine(listOf(p[0].replaceFirst(" ", sep), p[1])) }
        val e = assertFailsWith<KeykinException> { Slip39.combine(listOf(p[0].replace(" ", "\u00a0"), p[1])) }
        kotlin.test.assertTrue(e.message!!.contains("word 1 is not") && !e.message!!.contains(p[0].split(" ")[1]))
        for (x in listOf(-1, 16, 20)) assertFailsWith<KeykinException> { Slip39.generate(1, listOf(2 to 3), secret, "", x) }
        assertEquals(hex(secret), hex(Slip39.recoverBackup(listOf(p[0], p[2]))))
        val e6 = Slip39.generate(1, listOf(2 to 3), secret, "", 6)[0]
        assertFailsWith<KeykinException> { Slip39.recoverBackup(listOf(e6[0], e6[1])) }
    }
}
