// SLIP-0039 (satoshilabs/slips), the Kotlin counterpart of keykin/src/slip39.ts, written from the
// specification: GF(256) Shamir with a digest share, two levels, RS1024, and the Feistel encryption.
package keykin

import java.io.File
import java.math.BigInteger
import java.security.SecureRandom

object Slip39 {
    private const val RADIX = 10; private const val META_WORDS = 4; private const val CHECKSUM_WORDS = 3; private const val MIN_WORDS = 20
    private const val SECRET_INDEX = 255; private const val DIGEST_INDEX = 254; private const val DIGEST_LEN = 4
    val words: List<String> by lazy { File(System.getProperty("keykin.slip39words") ?: error("set keykin.slip39words")).readLines().filter { it.isNotBlank() } }
    private val index by lazy { words.withIndex().associate { it.value to it.index } }

    private val EXP = IntArray(255); private val LOG = IntArray(256)
    init { var x = 1; for (i in 0 until 255) { EXP[i] = x; LOG[x] = i; x = x xor ((x shl 1) xor (if (x and 0x80 != 0) 0x11b else 0)); x = x and 0xff } }
    private fun mul(a: Int, b: Int) = if (a == 0 || b == 0) 0 else EXP[(LOG[a] + LOG[b]) % 255]
    private fun div(a: Int, b: Int) = if (a == 0) 0 else EXP[(LOG[a] + 255 - LOG[b]) % 255]

    private fun interpolate(points: List<Pair<Int, ByteArray>>, x: Int): ByteArray {
        val xs = points.map { it.first }
        if (xs.toSet().size != xs.size) refuse("slip39", "share indices must be unique")
        val len = points[0].second.size
        if (points.any { it.second.size != len }) refuse("slip39", "share values must have one length")
        points.firstOrNull { it.first == x }?.let { return it.second }
        val out = IntArray(len)
        for ((xi, yi) in points) {
            var basis = 1
            for (xj in xs) if (xj != xi) basis = mul(basis, div(x xor xj, xi xor xj))
            for (k in 0 until len) out[k] = out[k] xor mul(yi[k].toInt() and 0xff, basis)
        }
        return ByteArray(len) { out[it].toByte() }
    }
    private fun digest(r: ByteArray, s: ByteArray) = hmac(r, s).copyOfRange(0, DIGEST_LEN)
    fun recover(t: Int, shares: List<Pair<Int, ByteArray>>): ByteArray {
        if (t == 1) return shares[0].second
        val s = interpolate(shares, SECRET_INDEX); val d = interpolate(shares, DIGEST_INDEX)
        if (!digest(d.copyOfRange(DIGEST_LEN, d.size), s).contentEquals(d.copyOfRange(0, DIGEST_LEN))) refuse("slip39", "invalid digest of the shared secret")
        return s
    }
    fun split(t: Int, n: Int, s: ByteArray, rnd: SecureRandom = SecureRandom()): List<ByteArray> {
        if (!(0 < t && t <= n && n <= 16)) refuse("slip39", "need 0 < T ≤ N ≤ 16")
        if (s.size * 8 < 128 || s.size % 2 != 0) refuse("slip39", "secret length")
        if (t == 1) return List(n) { s.copyOf() }
        val r = ByteArray(s.size - DIGEST_LEN).also(rnd::nextBytes)
        val d = digest(r, s) + r
        val random = List(t - 2) { ByteArray(s.size).also(rnd::nextBytes) }
        val base = random.mapIndexed { i, y -> i to y } + (DIGEST_INDEX to d) + (SECRET_INDEX to s)
        return List(n) { i -> if (i < t - 2) random[i] else interpolate(base, i) }
    }

    private val GEN = intArrayOf(0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120)
    private fun polymod(values: List<Int>): Int {
        var chk = 1
        for (v in values) { val b = chk ushr 20; chk = ((chk and 0xfffff) shl 10) xor v; for (i in 0 until 10) if ((b ushr i) and 1 == 1) chk = chk xor GEN[i] }
        return chk
    }
    private fun cs(ext: Boolean) = (if (ext) "shamir_extendable" else "shamir").map { it.code }
    fun verify(ext: Boolean, data: List<Int>) = polymod(cs(ext) + data) == 1
    fun checksum(ext: Boolean, data: List<Int>): List<Int> { val p = polymod(cs(ext) + data + listOf(0, 0, 0)) xor 1; return (0..2).map { (p ushr (10 * (2 - it))) and 1023 } }

    private fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, len: Int): ByteArray {
        val out = ByteArray(len); var block = 1; var off = 0
        while (off < len) {
            var u = hmac(password, salt + u32(block.toLong())); val t = u.copyOf()
            repeat(iterations - 1) { u = hmac(password, u); for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte() }
            t.copyInto(out, off, 0, minOf(32, len - off)); off += 32; block++
        }
        return out
    }
    private fun feistel(input: ByteArray, passphrase: String, e: Int, id: Int, ext: Boolean, order: List<Int>): ByteArray {
        if (passphrase.any { it.code < 32 || it.code > 126 }) refuse("slip39", "the passphrase is printable ASCII")
        val half = input.size / 2
        var l = input.copyOfRange(0, half); var r = input.copyOfRange(half, input.size)
        val salt = if (ext) ByteArray(0) else utf8("shamir") + byteArrayOf((id shr 8).toByte(), id.toByte())
        for (i in order) {
            val f = pbkdf2(byteArrayOf(i.toByte()) + utf8(passphrase), salt + r, (10000 / 4) shl e, half)
            val next = ByteArray(half) { (l[it].toInt() xor f[it].toInt()).toByte() }
            l = r; r = next
        }
        return r + l
    }
    fun encrypt(ms: ByteArray, p: String, e: Int, id: Int, ext: Boolean) = feistel(ms, p, e, id, ext, listOf(0, 1, 2, 3))
    fun decrypt(ems: ByteArray, p: String, e: Int, id: Int, ext: Boolean) = feistel(ems, p, e, id, ext, listOf(3, 2, 1, 0))

    data class Share(val id: Int, val ext: Boolean, val e: Int, val gi: Int, val gt: Int, val g: Int, val mi: Int, val mt: Int, val value: ByteArray)
    fun encode(s: Share): String {
        val padded = (s.value.size * 8 + RADIX - 1) / RADIX * RADIX
        var n = BigInteger.valueOf(s.id.toLong())
        for ((v, bits) in listOf((if (s.ext) 1 else 0) to 1, s.e to 4, s.gi to 4, (s.gt - 1) to 4, (s.g - 1) to 4, s.mi to 4, (s.mt - 1) to 4)) n = n.shiftLeft(bits).or(BigInteger.valueOf(v.toLong()))
        n = n.shiftLeft(padded).or(BigInteger(1, s.value))
        val count = (40 + padded) / RADIX
        val data = (0 until count).map { n.shiftRight(RADIX * (count - 1 - it)).and(BigInteger.valueOf(1023)).toInt() }
        return (data + checksum(s.ext, data)).joinToString(" ") { words[it] }
    }
    fun decode(mnemonic: String): Share {
        // The same separator set as TS: space, tab, line feed, carriage return; refusals name the position.
        val sep = Regex("[ \\t\\n\\r]+")
        val idx = mnemonic.replace(Regex("^[ \\t\\n\\r]+|[ \\t\\n\\r]+$"), "").split(sep).mapIndexed { k, w -> index[w.lowercase()] ?: refuse("slip39", "word ${k + 1} is not a SLIP-39 word") }
        if (idx.size < MIN_WORDS) refuse("slip39", "mnemonic too short")
        val pad = (RADIX * (idx.size - META_WORDS - CHECKSUM_WORDS)) % 16
        if (pad > 8) refuse("slip39", "invalid mnemonic length")
        val ext = (idx[1] shr 4) and 1 == 1
        if (!verify(ext, idx)) refuse("slip39", "invalid checksum")
        var n = BigInteger.ZERO; for (i in idx.dropLast(CHECKSUM_WORDS)) n = n.shiftLeft(10).or(BigInteger.valueOf(i.toLong()))
        val valueBits = RADIX * (idx.size - CHECKSUM_WORDS) - 40
        val meta = n.shiftRight(valueBits)
        fun f(shift: Int, bits: Int) = meta.shiftRight(shift).and(BigInteger.ONE.shiftLeft(bits) - BigInteger.ONE).toInt()
        val bytes = (valueBits - pad) / 8
        val v = n.and(BigInteger.ONE.shiftLeft(valueBits) - BigInteger.ONE)
        if (v.shiftRight(bytes * 8).signum() != 0) refuse("slip39", "invalid padding")
        val raw = v.toByteArray().let { if (it.size > bytes) it.copyOfRange(it.size - bytes, it.size) else ByteArray(bytes - it.size) + it }
        if (raw.size * 8 < 128) refuse("slip39", "invalid master secret length")
        return Share(f(25, 15), ext, f(20, 4), f(16, 4), f(12, 4) + 1, f(8, 4) + 1, f(4, 4), f(0, 4) + 1, raw)
    }
    fun combine(mnemonics: List<String>, passphrase: String = ""): ByteArray {
        if (mnemonics.isEmpty()) refuse("slip39", "no shares")
        val sh = mnemonics.map(::decode); val s0 = sh[0]
        if (sh.any { it.id != s0.id || it.ext != s0.ext || it.e != s0.e || it.gt != s0.gt || it.g != s0.g || it.value.size != s0.value.size }) refuse("slip39", "shares do not belong together")
        if (s0.g < s0.gt) refuse("slip39", "group threshold exceeds group count")
        val groups = sh.groupBy { it.gi }
        if (groups.size != s0.gt) refuse("slip39", "need exactly ${s0.gt} groups")
        val gshares = groups.map { (gi, ms) ->
            if (ms.map { it.mt }.toSet().size != 1) refuse("slip39", "member thresholds differ")
            if (ms.map { it.mi }.toSet().size != ms.size) refuse("slip39", "duplicate member index")
            if (ms.size != ms[0].mt) refuse("slip39", "wrong number of member shares")
            gi to recover(ms[0].mt, ms.map { it.mi to it.value })
        }
        return decrypt(recover(s0.gt, gshares), passphrase, s0.e, s0.id, s0.ext)
    }
    fun generate(gt: Int, groups: List<Pair<Int, Int>>, ms: ByteArray, passphrase: String = "", e: Int = 1, rnd: SecureRandom = SecureRandom()): List<List<String>> {
        if (ms.size * 8 < 128 || ms.size % 2 != 0) refuse("slip39", "master secret length")
        if (e !in 0..15) refuse("slip39", "iteration exponent")
        if (gt < 1 || gt > groups.size) refuse("slip39", "group threshold")
        if (groups.any { (t, n) -> t == 1 && n > 1 }) refuse("slip39", "a 1-of-N group is not allowed")
        val id = rnd.nextInt(1 shl 15)
        val gs = split(gt, groups.size, encrypt(ms, passphrase, e, id, true), rnd)
        return groups.mapIndexed { gi, (t, n) -> split(t, n, gs[gi], rnd).mapIndexed { mi, v -> encode(Share(id, true, e, gi, gt, groups.size, mi, t, v)) } }
    }
    /** Backup module §3's recovery: untrusted pieces must fit backupPieces' profile before any PBKDF2 runs. */
    fun recoverBackup(pieces: List<String>): ByteArray {
        for (s in pieces.map(::decode)) if (!s.ext || s.e != 1 || s.gt != 1 || s.g != 1 || s.gi != 0 || s.mt != 2 || s.value.size != 32) refuse("slip39", "not a Keykin backup piece")
        return combine(pieces)
    }
}
