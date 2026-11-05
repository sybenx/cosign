// The paper (Backup module §2), as the TS reference's src/backup.ts: the backup secret as 24 BIP-39 English
// words, the last 8 bits the first 8 of SHA-256("keykin-backup/1" ‖ secret), so a mistyped word is caught and a
// wallet seed (whose checksum is BIP-39's) is told apart.
package keykin

import java.math.BigInteger

object Backup {
    private val words: List<String> by lazy {
        (Backup::class.java.getResourceAsStream("/keykin/bip39-english.txt") ?: refuse("no_wordlist")).bufferedReader().readLines().filter { it.isNotBlank() }
    }
    private fun checkSecret(sk: ByteArray) { val k = BigInteger(1, sk); if (sk.size != 32 || k.signum() == 0 || k >= N) refuse("bad_backup", "not a secret key") }
    fun backupWords(sk: ByteArray): List<String> {
        checkSecret(sk)
        val bits = (sk + sha(utf8("keykin-backup/1"), sk)[0]).joinToString("") { (it.toInt() and 0xff).toString(2).padStart(8, '0') }
        return (0 until 24).map { k -> words[bits.substring(11 * k, 11 * k + 11).toInt(2)] }
    }
    fun readBackupWords(typed: List<String>): ByteArray {
        if (typed.size != 24) refuse("bad_backup", "24 words")
        val idx = typed.map { words.indexOf(it.lowercase().trim()) }
        if (idx.any { it < 0 }) refuse("bad_backup", "not a backup word")
        val bits = idx.joinToString("") { it.toString(2).padStart(11, '0') }
        val bytes = ByteArray(33) { k -> bits.substring(8 * k, 8 * k + 8).toInt(2).toByte() }
        val sk = bytes.copyOf(32)
        if (sha(utf8("keykin-backup/1"), sk)[0] != bytes[32]) {
            // BIP-39's checksum for 256 bits of entropy is the first 8 bits of SHA-256(entropy).
            if (sha(sk)[0] == bytes[32]) refuse("wallet_seed", "This looks like a wallet seed, not a Keykin backup")
            refuse("bad_backup", "checksum")
        }
        checkSecret(sk)
        return sk
    }
}
