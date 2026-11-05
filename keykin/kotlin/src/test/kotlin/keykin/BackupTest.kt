package keykin

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** vectors/backup-words.json, made by the TS reference: the paper's 24 words both ways; refusals told apart. */
class BackupTest {
    private val v = JSONObject(File(System.getProperty("keykin.backupwords")).readText())
    private fun words(a: org.json.JSONArray) = (0 until a.length()).map { a.getString(it) }
    @Test fun wordsBothWays() {
        val ok = v.getJSONArray("valid")
        for (k in 0 until ok.length()) {
            val x = ok.getJSONObject(k)
            assertEquals(words(x.getJSONArray("words")), Backup.backupWords(unhex(x.getString("secret"))))
            assertEquals(x.getString("secret"), hex(Backup.readBackupWords(words(x.getJSONArray("words")))))
            assertEquals(x.getString("secret"), hex(Backup.readBackupWords(words(x.getJSONArray("words")).map { " ${it.uppercase()} " })), "case and spaces")
        }
        assertEquals("bad_backup", assertFailsWith<KeykinException> { Backup.readBackupWords(words(v.getJSONArray("refused").getJSONObject(0).getJSONArray("words"))) }.code)
        assertEquals("wallet_seed", assertFailsWith<KeykinException> { Backup.readBackupWords(words(v.getJSONArray("wallet_seed"))) }.code)
    }
}
